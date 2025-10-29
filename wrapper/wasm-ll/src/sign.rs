// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::str::FromStr;

use derivation_path::DerivationPath;
use js_sys::{Array, Error, Uint8Array};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use dkls23_ll::dsg;

use crate::{
    errors::sign_error,
    keyshare::Keyshare,
    maybe_seeded_rng,
    message::{Message, MessageRouting},
};

#[derive(Serialize, Deserialize)]
enum Round {
    Init,
    WaitMsg1,
    WaitMsg2,
    WaitMsg3,
    Pre(dsg::PreSignature),
    WaitMsg4(dsg::PartialSignature),
    Failed,
    Finished,
}

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
    pub fn new(
        keyshare: Keyshare,
        chain_path: &str,
        seed: Option<Vec<u8>>,
    ) -> Self {
        let mut rng = maybe_seeded_rng(seed);

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
    pub fn error(&self) -> Option<Error> {
        match &self.round {
            Round::Failed => Some(Error::new("failed")),
            _ => None,
        }
    }

    /// Create a fist message and change session state from Init to WaitMg1.
    #[wasm_bindgen(js_name = createFirstMessage)]
    pub fn create_first_message(&mut self) -> Result<Message, Error> {
        match self.round {
            Round::Init => {
                self.round = Round::WaitMsg1;
                Ok(Message::new(self.state.generate_msg1()))
            }

            _ => Err(Error::new("invalid state")),
        }
    }

    fn handle<T, U, H>(
        &mut self,
        msgs: Vec<Message>,
        mut h: H,
        next: Round,
    ) -> Result<Vec<Message>, Error>
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

            Err(err) => {
                self.round = Round::Failed;
                Err(sign_error(err))
            }
        }
    }

    /// Handle a batch of messages.
    /// Decode, process and return an array messages to send to other parties.
    #[wasm_bindgen(js_name = handleMessages)]
    pub fn handle_messages(
        &mut self,
        msgs: Vec<Message>,
        seed: Option<Vec<u8>>,
    ) -> Result<Vec<Message>, Error> {
        let mut rng = maybe_seeded_rng(seed);

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
                let pre = self.state.handle_msg3(msgs).map_err(sign_error)?;

                self.round = Round::Pre(pre);

                Ok(vec![])
            }

            Round::Failed => Err(Error::new("failed")),

            _ => Err(Error::new("invalid session state")),
        }
    }

    /// The session contains a "pre-signature".
    /// Returns a last message.
    #[wasm_bindgen(js_name = lastMessage)]
    pub fn last_message(
        &mut self,
        message_hash: &[u8],
    ) -> Result<Message, Error> {
        if message_hash.len() != 32 {
            return Err(Error::new("invalid message hash"));
        }

        match core::mem::replace(&mut self.round, Round::Finished) {
            Round::Pre(pre) => {
                let hash = message_hash.try_into().unwrap();
                let (partial, msg4) =
                    dsg::create_partial_signature(pre, hash);

                self.round = Round::WaitMsg4(partial);

                Ok(Message::new(msg4))
            }

            prev => {
                self.round = prev;
                Err(Error::new("invalid state"))
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
    ) -> Result<Array, Error> {
        match self.round {
            Round::WaitMsg4(partial) => {
                let msgs = Message::decode_vector(&msgs);
                let sign = dsg::combine_signatures(partial, msgs)
                    .map_err(sign_error)?;

                let (r, s) = sign.split_bytes();

                let a = js_sys::Array::new_with_length(2);

                a.set(0, Uint8Array::from(&r as &[u8]).into());
                a.set(1, Uint8Array::from(&s as &[u8]).into());

                Ok(a)
            }

            _ => Err(Error::new("invalid state")),
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

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::keygen::tests::run_dkg;
    use wasm_bindgen_test::*;

    fn filter_messages(msgs: &[Message], party_id: u8) -> Vec<Message> {
        msgs.iter()
            .filter(|msg| msg.from_id != party_id)
            .map(|msg| msg.clone())
            .collect()
    }

    fn select_messages(msgs: &[Message], party_id: u8) -> Vec<Message> {
        msgs.iter()
            .filter(|msg| msg.to_id == Some(party_id))
            .map(|msg| msg.clone())
            .collect()
    }

    fn signatures_equal(sig1: &Array, sig2: &Array) -> bool {
        if sig1.length() != sig2.length() {
            return false;
        }

        for i in 0..sig1.length() {
            let arr1 = sig1.get(i).dyn_into::<Uint8Array>().unwrap();
            let arr2 = sig2.get(i).dyn_into::<Uint8Array>().unwrap();

            if arr1.length() != arr2.length() {
                return false;
            }

            let bytes1: Vec<u8> = arr1.to_vec();
            let bytes2: Vec<u8> = arr2.to_vec();

            if bytes1 != bytes2 {
                return false;
            }
        }

        true
    }

    pub fn run_dsg(
        shares: &[Keyshare],
        t: usize,
        message_hash: &[u8],
    ) -> Vec<Array> {
        let mut parties: Vec<SignSession> = shares[..t]
            .iter()
            .map(|share| SignSession::new((*share).clone(), "m", None))
            .collect();

        // Round 1: Create first messages
        let msg1: Vec<Message> = parties
            .iter_mut()
            .map(|p| p.create_first_message().unwrap())
            .collect();

        // Round 2: Handle first messages
        let mut msg2: Vec<Message> = Vec::new();
        for (i, party) in parties.iter_mut().enumerate() {
            let batch = filter_messages(&msg1, i as u8);
            msg2.extend(party.handle_messages(batch, None).unwrap());
        }

        // Round 3: Handle second messages
        let mut msg3: Vec<Message> = Vec::new();
        for (i, party) in parties.iter_mut().enumerate() {
            let batch = select_messages(&msg2, i as u8);
            msg3.extend(party.handle_messages(batch, None).unwrap());
        }

        // Round 4: Handle third messages and create partial signatures
        for (i, party) in parties.iter_mut().enumerate() {
            let batch = select_messages(&msg3, i as u8);
            party.handle_messages(batch, None).unwrap();
        }

        // Create last messages with message hash
        let msg4: Vec<Message> = parties
            .iter_mut()
            .map(|p| p.last_message(message_hash).unwrap())
            .collect();

        // Combine signatures
        let signatures: Vec<Array> = parties
            .into_iter()
            .enumerate()
            .map(|(i, party)| {
                let batch = filter_messages(&msg4, i as u8);
                party.combine_partial_signature(batch).unwrap()
            })
            .collect();

        signatures
    }

    #[wasm_bindgen_test]
    fn dsg_2_out_of_2() {
        let shares = run_dkg(2, 2);
        let message_hash = vec![255u8; 32];

        let signatures = run_dsg(&shares, 2, &message_hash);

        let sig0 = &signatures[0];
        for sig in &signatures[1..] {
            assert!(
                signatures_equal(sig0, sig),
                "Signatures should be identical"
            );
        }

        let r = signatures[0].get(0).dyn_into::<Uint8Array>().unwrap();
        let s = signatures[0].get(1).dyn_into::<Uint8Array>().unwrap();

        let r_bytes: Vec<u8> = r.to_vec();
        let s_bytes: Vec<u8> = s.to_vec();

        let public_key_bytes: Vec<u8> = shares[0].public_key().to_vec();

        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        use k256::ecdsa::{Signature, VerifyingKey};
        use k256::elliptic_curve::ops::Reduce;
        use k256::U256;

        let r_scalar = k256::Scalar::reduce(U256::from_be_slice(&r_bytes));
        let s_scalar = k256::Scalar::reduce(U256::from_be_slice(&s_bytes));

        let signature = Signature::from_scalars(r_scalar, s_scalar)
            .expect("Failed to create signature from r and s");

        let verifying_key = VerifyingKey::from_sec1_bytes(&public_key_bytes)
            .expect("Failed to create verifying key from public key bytes");

        verifying_key
            .verify_prehash(&message_hash, &signature)
            .expect("Signature verification failed");
    }

    #[wasm_bindgen_test]
    fn dsg_2_out_of_3() {
        let shares = run_dkg(3, 2);
        let message_hash = vec![255u8; 32];

        let signatures = run_dsg(&shares, 2, &message_hash);

        let sig0 = &signatures[0];
        for sig in &signatures[1..] {
            assert!(
                signatures_equal(sig0, sig),
                "Signatures should be identical"
            );
        }
    }
}
