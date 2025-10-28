// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use js_sys::{Array, Error, Uint8Array};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use k256::{elliptic_curve::group::GroupEncoding, AffinePoint};

use dkls23_ll::dkg::{self, KeygenError};

use crate::{
    errors::keygen_error,
    keyshare::Keyshare,
    maybe_seeded_rng,
    message::{Message, MessageRouting},
};

#[derive(Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
enum Round {
    Init,
    WaitMsg1,
    WaitMsg2,
    WaitMsg3,
    WaitMsg4,
    Failed,
    Share(dkg::Keyshare),
}

#[derive(Serialize, Deserialize)]
#[wasm_bindgen]
pub struct KeygenSession {
    state: dkg::State,
    n: usize,
    round: Round,
}

#[wasm_bindgen]
impl KeygenSession {
    #[wasm_bindgen(constructor)]
    pub fn new(
        participants: u8,
        threshold: u8,
        party_id: u8,
        seed: Option<Vec<u8>>,
    ) -> Self {
        let mut rng = maybe_seeded_rng(seed);

        let party = dkg::Party {
            ranks: vec![0; participants as usize],
            t: threshold,
            party_id,
        };

        KeygenSession {
            n: party.ranks.len(),
            state: dkg::State::new(party, &mut rng),
            round: Round::Init,
        }
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = vec![];
        ciborium::into_writer(self, &mut buffer)
            .expect_throw("CBOR encode error");

        buffer
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> KeygenSession {
        ciborium::from_reader(bytes).expect_throw("CBOR decode")
    }

    #[wasm_bindgen(js_name = initKeyRotation)]
    pub fn init_key_rotation(
        oldshare: &Keyshare,
        seed: Option<Vec<u8>>,
    ) -> Result<KeygenSession, Error> {
        let oldshare = oldshare.as_ref();
        let mut rng = maybe_seeded_rng(seed);

        Ok(KeygenSession {
            n: oldshare.rank_list.len(),
            state: dkg::State::key_rotation(oldshare, &mut rng)
                .map_err(keygen_error)?,
            round: Round::Init,
        })
    }

    #[wasm_bindgen(js_name = initKeyRecovery)]
    pub fn init_key_recover(
        oldshare: &Keyshare,
        lost_shares: Vec<u8>,
        seed: Option<Vec<u8>>,
    ) -> Result<KeygenSession, Error> {
        let mut rng = maybe_seeded_rng(seed);

        let oldshare = oldshare.as_ref();

        Ok(KeygenSession {
            n: oldshare.rank_list.len(),
            state: dkg::State::key_refresh(
                &dkg::RefreshShare::from_keyshare(
                    oldshare,
                    Some(&lost_shares),
                ),
                &mut rng,
            )
            .map_err(keygen_error)?,
            round: Round::Init,
        })
    }

    #[wasm_bindgen(js_name = initLostShareRecovery)]
    pub fn init_lost_share_recover(
        participants: u8,
        threshold: u8,
        party_id: u8,
        pk: Vec<u8>,
        lost_shares: Vec<u8>,
        seed: Option<Vec<u8>>,
    ) -> Result<KeygenSession, Error> {
        let mut rng = maybe_seeded_rng(seed);

        let party = dkg::Party {
            ranks: vec![0; participants as usize],
            t: threshold,
            party_id,
        };

        let pk: [u8; 33] =
            pk.try_into().map_err(|_| Error::new("invalid PK size"))?;
        let pk: Option<AffinePoint> =
            AffinePoint::from_bytes(&pk.into()).into();
        let pk = pk.ok_or_else(|| Error::new("invalid PK"))?;

        Ok(KeygenSession {
            n: participants as _,
            state: dkg::State::key_refresh(
                &dkg::RefreshShare::from_lost_keyshare(
                    party,
                    pk,
                    lost_shares,
                ),
                &mut rng,
            )
            .map_err(keygen_error)?,
            round: Round::Init,
        })
    }

    #[wasm_bindgen(js_name = error)]
    pub fn error(&self) -> Option<Error> {
        match &self.round {
            Round::Failed => Some(Error::new("failed")),
            _ => None,
        }
    }

    /// Finish key generation session and return resulting key share.
    /// This nethod consumes the session and deallocates it in any
    /// case, even if the session is not finished and key share is
    /// not avialable or an error occured before.
    #[wasm_bindgen(js_name = keyshare)]
    pub fn keyshare(self) -> Result<Keyshare, Error> {
        match self.round {
            Round::Share(share) => Ok(Keyshare::new(share)),
            Round::Failed => Err(Error::new("failed")),
            _ => Err(Error::new("keygen-in-progress")),
        }
    }

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

    #[wasm_bindgen(js_name = calculateChainCodeCommitment)]
    pub fn calculate_commitment_2(&self) -> Vec<u8> {
        self.state.calculate_commitment_2().to_vec()
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
        H: FnMut(&mut dkg::State, Vec<T>) -> Result<Vec<U>, dkg::KeygenError>,
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
                Err(keygen_error(err))
            }
        }
    }

    // , typescript_type = "handleMessages(msgs: (Message)[], commitments?: Array<Uint8Array>): (Message)[]"
    #[wasm_bindgen(js_name = handleMessages)]
    pub fn handle_messages(
        &mut self,
        msgs: Vec<Message>,
        commitments: Option<Array>,
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
                let commitments = commitments.ok_or_else(|| {
                    keygen_error(KeygenError::InvalidMessage)
                })?;
                let len = self.n as u32;
                if commitments.length() != len {
                    return Err(keygen_error(KeygenError::InvalidMessage));
                }

                let commitments: Vec<_> = commitments
                    .into_iter()
                    .map(|bytes| match bytes.dyn_into::<Uint8Array>() {
                        Ok(bytes) if bytes.length() == 32 => {
                            let mut b = [0u8; 32];
                            bytes.copy_to(&mut b);
                            Ok(b)
                        }
                        _ => Err(keygen_error(
                            KeygenError::InvalidCommitmentHash,
                        )),
                    })
                    .collect::<Result<Vec<_>, js_sys::Error>>()?;

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
                match self.state.handle_msg4(msgs) {
                    Ok(keyshare) => self.round = Round::Share(keyshare),
                    Err(err) => {
                        self.round = Round::Failed;
                        return Err(keygen_error(err));
                    }
                };

                Ok(vec![])
            }

            Round::Failed => Err(Error::new("failed session")),

            _ => Err(Error::new("invalid session state")),
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

#[cfg(test)]
pub mod tests {
    use super::*;
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

    pub fn run_dkg(n: u8, t: u8) -> Vec<Keyshare> {
        let mut parties: Vec<KeygenSession> =
            (0..n).map(|i| KeygenSession::new(n, t, i, None)).collect();

        let msg1: Vec<Message> = parties
            .iter_mut()
            .map(|p| p.create_first_message().unwrap())
            .collect();

        let mut msg2: Vec<Message> = Vec::new();
        for (i, party) in parties.iter_mut().enumerate() {
            let batch = filter_messages(&msg1, i as u8);
            msg2.extend(party.handle_messages(batch, None, None).unwrap());
        }

        let mut msg3: Vec<Message> = Vec::new();
        for (i, party) in parties.iter_mut().enumerate() {
            let batch = select_messages(&msg2, i as u8);
            msg3.extend(party.handle_messages(batch, None, None).unwrap());
        }

        let commitments: Array = parties
            .iter()
            .map(|p| Uint8Array::from(p.calculate_commitment_2().as_ref()))
            .collect::<js_sys::Array>()
            .into();

        let mut msg4: Vec<Message> = Vec::new();
        for (i, party) in parties.iter_mut().enumerate() {
            let batch = select_messages(&msg3, i as u8);
            msg4.push(
                party
                    .handle_messages(batch, Some(commitments.clone()), None)
                    .unwrap()
                    .pop()
                    .unwrap(),
            );
        }

        for (i, party) in parties.iter_mut().enumerate() {
            let batch = filter_messages(&msg4, i as u8);
            party.handle_messages(batch, None, None).unwrap();
        }

        // Extract keyshares
        parties.into_iter().map(|p| p.keyshare().unwrap()).collect()
    }

    #[wasm_bindgen_test]
    fn dkg_2_out_of_2() {
        let shares = run_dkg(2, 2);
        assert_eq!(shares.len(), 2);

        let pk0 = shares[0].public_key();
        let pk1 = shares[1].public_key();
        assert_eq!(pk0.to_vec(), pk1.to_vec());

    }

    #[wasm_bindgen_test]
    fn dkg_2_out_of_3() {
        let shares = run_dkg(3, 2);
        assert_eq!(shares.len(), 3);

        let pk0 = shares[0].public_key();
        for share in &shares[1..] {
            assert_eq!(pk0.to_vec(), share.public_key().to_vec());
        }
    }
}
