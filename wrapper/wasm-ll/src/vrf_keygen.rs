// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use js_sys::Error;
use wasm_bindgen::prelude::*;

use dkls23_ll::vrf::dkg::{self, VrfKeygenMsg1, VrfKeygenMsg2};

use crate::{
    errors::vrf_keygen_error,
    maybe_seeded_rng,
    message::Message,
    vrf_keyshare::VrfKeyshare,
    vrf_session::{
        decode_messages, encode_message, encode_messages, peer_messages,
        PartyMessage,
    },
};

#[allow(clippy::large_enum_variant)]
enum Round {
    Init,
    WaitMsg1,
    WaitMsg2,
    Failed,
    Share(dkls23_ll::vrf::VrfKeyshare),
}

#[wasm_bindgen]
pub struct VrfKeygenSession {
    state: dkg::State,
    n: usize,
    party_id: u8,
    round: Round,
}

#[wasm_bindgen]
impl VrfKeygenSession {
    #[wasm_bindgen(constructor)]
    pub fn new(
        participants: u8,
        threshold: u8,
        party_id: u8,
        seed: Option<Vec<u8>>,
    ) -> Result<VrfKeygenSession, Error> {
        let mut rng = maybe_seeded_rng(seed);

        let state = dkg::State::new(
            dkg::Party::new(participants, threshold, party_id),
            &mut rng,
        )
        .map_err(vrf_keygen_error)?;

        Ok(VrfKeygenSession {
            state,
            n: participants as usize,
            party_id,
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

    #[wasm_bindgen(js_name = vrfKeyshare)]
    pub fn vrf_keyshare(self) -> Result<VrfKeyshare, Error> {
        match self.round {
            Round::Share(share) => Ok(VrfKeyshare::new(share)),
            Round::Failed => Err(Error::new("failed")),
            _ => Err(Error::new("vrf-keygen-in-progress")),
        }
    }

    #[wasm_bindgen(js_name = createFirstMessage)]
    pub fn create_first_message(
        &mut self,
        seed: Option<Vec<u8>>,
    ) -> Result<Message, Error> {
        let mut rng = maybe_seeded_rng(seed);

        match self.round {
            Round::Init => match self.state.generate_msg1(&mut rng) {
                Ok(msg) => {
                    self.round = Round::WaitMsg1;
                    Ok(encode_message(msg))
                }
                Err(err) => {
                    self.round = Round::Failed;
                    Err(vrf_keygen_error(err))
                }
            },
            Round::Failed => Err(Error::new("failed session")),
            _ => Err(Error::new("invalid state")),
        }
    }

    #[wasm_bindgen(js_name = handleMessages)]
    pub fn handle_messages(
        &mut self,
        msgs: Vec<Message>,
        seed: Option<Vec<u8>>,
    ) -> Result<Vec<Message>, Error> {
        let mut rng = maybe_seeded_rng(seed);

        match &self.round {
            Round::WaitMsg1 => {
                if msgs.len() + 1 != self.n {
                    return Err(Error::new("invalid message count"));
                }
                let decoded = decode_messages::<VrfKeygenMsg1>(&msgs);
                let peers = peer_messages(decoded, self.party_id);
                match self.state.handle_msg1(&mut rng, peers) {
                    Ok(msg2) => {
                        self.round = Round::WaitMsg2;
                        Ok(encode_messages(vec![msg2]))
                    }
                    Err(err) => {
                        self.round = Round::Failed;
                        Err(vrf_keygen_error(err))
                    }
                }
            }

            Round::WaitMsg2 => {
                if msgs.len() != self.n {
                    return Err(Error::new("invalid message count"));
                }
                let decoded = decode_messages::<VrfKeygenMsg2>(&msgs);
                match self.state.handle_msg2(decoded) {
                    Ok(share) => {
                        self.round = Round::Share(share);
                        Ok(vec![])
                    }
                    Err(err) => {
                        self.round = Round::Failed;
                        Err(vrf_keygen_error(err))
                    }
                }
            }

            Round::Failed => Err(Error::new("failed session")),
            _ => Err(Error::new("invalid session state")),
        }
    }
}

impl crate::message::MessageRouting for VrfKeygenMsg1 {
    fn src_party_id(&self) -> u8 {
        self.from_party
    }

    fn dst_party_id(&self) -> Option<u8> {
        None
    }
}

impl crate::message::MessageRouting for VrfKeygenMsg2 {
    fn src_party_id(&self) -> u8 {
        self.from_party
    }

    fn dst_party_id(&self) -> Option<u8> {
        None
    }
}

impl PartyMessage for VrfKeygenMsg1 {
    fn party_id(&self) -> u8 {
        self.from_party
    }
}
