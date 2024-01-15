use core::mem;

use js_sys::{Array, Uint8Array};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use wasm_bindgen::{prelude::*, throw_str};

use dkls23_ll::dkg;
use sl_mpc_mate::HashBytes;

use crate::keyshare::Keyshare;
use crate::message::{Message, MessageRouting};

#[derive(Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
enum Round {
    Init,
    WaitMsg1,
    WaitMsg2,
    WaitMsg3,
    WaitMsg4,
    Error(String),
    Share(dkg::Keyshare),
    Ended,
}

///
#[derive(Serialize, Deserialize)]
#[wasm_bindgen]
pub struct KeygenSession {
    state: dkg::State,
    round: Round,
}

#[wasm_bindgen]
impl KeygenSession {
    #[wasm_bindgen(constructor)]
    pub fn new(participants: u8, threshold: u8, party_id: u8) -> Self {
        let party = dkg::Party {
            ranks: vec![0; participants as usize],
            t: threshold,
            party_id,
        };

        let mut rng = rand::thread_rng();

        KeygenSession {
            state: dkg::State::new(party, &mut rng, None),
            round: Round::Init,
        }
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = vec![];
        ciborium::into_writer(self, &mut buffer).expect_throw("CBOR encode error");

        buffer
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> KeygenSession {
        ciborium::from_reader(bytes).expect_throw("CBOR decode")
    }

    #[wasm_bindgen(js_name = initKeyRotation)]
    pub fn init_key_rotation(oldshare: Keyshare) -> Self {
        let oldshare = oldshare.into_inner();
        let party_id = oldshare.party_id as usize;

        let party = dkg::Party {
            ranks: oldshare.rank_list.clone(),
            t: oldshare.threshold,
            party_id: oldshare.party_id,
        };

        let mut rng = rand::thread_rng();

        KeygenSession {
            state: dkg::State::new(party, &mut rng, Some(&oldshare.x_i_list[party_id])),
            round: Round::Init,
        }
    }

    #[wasm_bindgen(js_name = error)]
    pub fn error(&self) -> Option<String> {
        match &self.round {
            Round::Error(err) => Some(err.clone()),
            _ => None,
        }
    }

    pub fn keyshare(&mut self) -> Result<Keyshare, JsError> {
        match mem::replace(&mut self.round, Round::Ended) {
            Round::Share(share) => Ok(Keyshare::new(share)),
            prev => {
                self.round = prev;
                Err(JsError::new("keygen is not finished"))
            }
        }
    }

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

    #[wasm_bindgen(js_name = calculateChainCodeCommitment)]
    pub fn calculate_commitment_2(&self) -> Vec<u8> {
        self.state.calculate_commitment_2().to_vec()
    }

    fn handle<T: DeserializeOwned, U: Serialize + MessageRouting, H>(
        &mut self,
        msgs: Vec<Message>,
        mut h: H,
        next: Round,
    ) -> Result<Vec<Message>, JsError>
    where
        H: FnMut(&mut dkg::State, Vec<T>) -> Result<Vec<U>, dkg::KeygenError>,
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

    // , typescript_type = "handleMessages(msgs: (Message)[], commitments?: Array<Uint8Array>): (Message)[]"
    #[wasm_bindgen(js_name = handleMessages)]
    pub fn handle_messages(
        &mut self,
        msgs: Vec<Message>,
        commitments: Option<Array>,
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
                let commitments = commitments.ok_or_else(|| JsError::new("missing commitments"))?;
                let len = self.state.ranks.len() as u32;
                if commitments.length() != len {
                    return Err(JsError::new("invalid number of commitments"));
                }

                let commitments: Vec<_> = commitments
                    .iter()
                    .map(|bytes| match bytes.dyn_into::<Uint8Array>() {
                        Ok(bytes) if bytes.length() == 32 => {
                            let mut b = [0u8; 32];
                            bytes.copy_to(&mut b);
                            Ok(HashBytes::new(b))
                        }
                        _ => Err(JsError::new("invalid commitment")),
                    })
                    .collect::<Result<Vec<_>, JsError>>()?;

                self.handle(
                    msgs,
                    |state, msgs| {
                        state
                            .handle_msg3(&mut rng, msgs, &commitments)
                            .map(|m| vec![m])
                    },
                    Round::WaitMsg4,
                )
            }

            Round::WaitMsg4 => {
                let msgs = Message::decode_vector(&msgs);
                let keyshare = self
                    .state
                    .handle_msg4(msgs)
                    .expect_throw("handle message 4");

                self.round = Round::Share(keyshare);

                Ok(vec![])
            }

            Round::Error(err) => Err(JsError::new(err.as_ref())),

            _ => Err(JsError::new("invalid session state")),
        }
    }
}

impl MessageRouting for dkg::KeygenMsg1 {
    fn src_party_id(&self) -> u8 {
        self.from_id
    }

    fn dst_party_id(&self) -> Option<u8> {
        None
    }
}

impl MessageRouting for dkg::KeygenMsg2 {
    fn src_party_id(&self) -> u8 {
        self.from_id
    }

    fn dst_party_id(&self) -> Option<u8> {
        Some(self.to_id)
    }
}

impl MessageRouting for dkg::KeygenMsg3 {
    fn src_party_id(&self) -> u8 {
        self.from_id
    }

    fn dst_party_id(&self) -> Option<u8> {
        Some(self.to_id)
    }
}

impl MessageRouting for dkg::KeygenMsg4 {
    fn src_party_id(&self) -> u8 {
        self.from_id
    }

    fn dst_party_id(&self) -> Option<u8> {
        None
    }
}
