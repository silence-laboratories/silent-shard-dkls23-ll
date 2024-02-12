use std::str::FromStr;

use derivation_path::DerivationPath;
use js_sys::{Array, Uint8Array};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use wasm_bindgen::{prelude::*, throw_str};

use dkls23_ll::dsg;

use crate::keyshare::Keyshare;
use crate::message::{Message, MessageRouting};

#[derive(Serialize, Deserialize)]
enum Round {
    Init,
    WaitMsg1,
    WaitMsg2,
    WaitMsg3,
    Pre(dsg::PreSignature),
    WaitMsg4(dsg::PartialSignature),
    Error(String),
    Sign(Vec<u8>),
    Invalid,
}

///
#[derive(Serialize, Deserialize)]
#[wasm_bindgen]
pub struct SignSession {
    state: dsg::State,
    round: Round,
}

#[wasm_bindgen]
impl SignSession {
    /// Create a new session.
    #[wasm_bindgen(constructor)]
    pub fn new(keyshare: Keyshare, chain_path: &str) -> Self {
        let mut rng = rand::thread_rng();

        let chain_path = DerivationPath::from_str(chain_path)
            .expect_throw("invalid derivation path");

        let state =
            dsg::State::new(&mut rng, keyshare.into_inner(), &chain_path)
                .expect_throw("sign session init");

        SignSession {
            state,
            round: Round::Init,
        }
    }

    /// Serialize session into array of bytes.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = vec![];
        ciborium::into_writer(self, &mut buffer)
            .expect_throw("CBOR encode error");

        buffer
    }

    /// Deserialize session from array of bytes.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> SignSession {
        ciborium::from_reader(bytes).expect_throw("CBOR decode error")
    }

    /// Return an error message, if any.
    #[wasm_bindgen(js_name = error)]
    pub fn error(&self) -> Option<String> {
        match &self.round {
            Round::Error(err) => Some(err.clone()),
            _ => None,
        }
    }

    /// Create a fist message and change session state from Init to WaitMg1.
    #[wasm_bindgen(js_name = createFirstMessage)]
    pub fn create_first_message(&mut self) -> Message {
        if !matches!(self.round, Round::Init) {
            throw_str("invalid state");
        }

        let msg1 = self.state.generate_msg1();
        let msg1 = Message::new(msg1);

        self.round = Round::WaitMsg1;

        msg1
    }

    fn handle<T, U, H>(
        &mut self,
        msgs: Vec<Message>,
        mut h: H,
        next: Round,
    ) -> Result<Vec<Message>, JsError>
    where
        T: DeserializeOwned,
        U: Serialize + MessageRouting,
        H: FnMut(&mut dsg::State, Vec<T>) -> Result<Vec<U>, dsg::SignError>,
    {
        let msgs: Vec<T> = Message::decode_vector(&msgs);
        match h(&mut self.state, msgs) {
            Ok(msgs) => {
                let out = Message::encode_vector(msgs);
                self.round = next;
                Ok(out)
            }

            Err(_) => {
                self.round = Round::Error("process message".into());
                Err(JsError::new("process message"))
            }
        }
    }

    /// Handle a batch of messages.
    /// Decode, process and return an array messages to send to other parties.
    #[wasm_bindgen(js_name = handleMessages)]
    pub fn handle_messages(
        &mut self,
        msgs: Vec<Message>,
    ) -> Result<Vec<Message>, JsError> {
        let mut rng = rand::thread_rng();

        match &self.round {
            Round::WaitMsg1 => self.handle(
                msgs,
                |state, msgs| state.handle_msg1(&mut rng, msgs),
                Round::WaitMsg2,
            ),

            Round::WaitMsg2 => self.handle(
                msgs,
                |state, msgs| state.handle_msg2(&mut rng, msgs),
                Round::WaitMsg3,
            ),

            Round::WaitMsg3 => {
                let msgs = Message::decode_vector(&msgs);
                let pre = self
                    .state
                    .handle_msg3(msgs)
                    .expect_throw("handle message 3");

                self.round = Round::Pre(pre);

                Ok(vec![])
            }

            Round::Error(err) => Err(JsError::new(err.as_ref())),

            _ => Err(JsError::new("invalid session state")),
        }
    }

    /// The session contains a "pre-signature".
    /// Returns a last message.
    #[wasm_bindgen(js_name = lastMessage)]
    pub fn last_message(
        &mut self,
        message_hash: &[u8],
    ) -> Result<Message, JsError> {
        if message_hash.len() != 32 {
            return Err(JsError::new("invalid message hash"));
        }

        match core::mem::replace(&mut self.round, Round::Invalid) {
            Round::Pre(pre) => {
                let hash = message_hash.try_into().unwrap();
                let (partial, msg4) =
                    dsg::create_partial_signature(pre, hash);

                self.round = Round::WaitMsg4(partial);

                Ok(Message::new(msg4))
            }

            prev => {
                self.round = prev;
                Err(JsError::new("invalid state"))
            }
        }
    }

    /// Combine last messages and return signature as [R, S].
    /// R, S are 32 byte UintArray.
    ///
    /// This method consumes the session and deallocates all
    /// internal data.
    ///
    #[wasm_bindgen(js_name = combine)]
    pub fn combine_partial_signature(
        self,
        msgs: Vec<Message>,
    ) -> Result<Array, JsError> {
        match self.round {
            Round::WaitMsg4(partial) => {
                let msgs = Message::decode_vector(&msgs);
                let sign = dsg::combine_signatures(partial, msgs)
                    .map_err(|_| JsError::new("combine error"))?;

                let (r, s) = sign.split_bytes();

                let a = js_sys::Array::new_with_length(2);

                a.set(0, Uint8Array::from(&r as &[u8]).into());
                a.set(1, Uint8Array::from(&s as &[u8]).into());

                Ok(a)
            }

            _ => Err(JsError::new("invalid state")),
        }
    }
}

impl MessageRouting for dsg::SignMsg1 {
    fn src_party_id(&self) -> u8 {
        self.from_id
    }

    fn dst_party_id(&self) -> Option<u8> {
        None
    }
}

impl MessageRouting for dsg::SignMsg2 {
    fn src_party_id(&self) -> u8 {
        self.from_id
    }

    fn dst_party_id(&self) -> Option<u8> {
        Some(self.to_id)
    }
}

impl MessageRouting for dsg::SignMsg3 {
    fn src_party_id(&self) -> u8 {
        self.from_id
    }

    fn dst_party_id(&self) -> Option<u8> {
        Some(self.to_id)
    }
}

impl MessageRouting for dsg::SignMsg4 {
    fn src_party_id(&self) -> u8 {
        self.from_id
    }

    fn dst_party_id(&self) -> Option<u8> {
        None
    }
}

impl MessageRouting for dsg::PreSignature {
    fn src_party_id(&self) -> u8 {
        self.from_id
    }

    fn dst_party_id(&self) -> Option<u8> {
        None
    }
}
