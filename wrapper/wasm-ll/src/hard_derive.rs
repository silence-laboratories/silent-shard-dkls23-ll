// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use js_sys::Error;
use wasm_bindgen::prelude::*;

use dkls23_ll::vrf::hard_derivation::{
    self, keyshare_after_hard_derive, HardDeriveMsg0, HardDeriveMsg1,
    MpcDeriveInit,
};

use crate::{
    errors::hard_derive_error,
    keyshare::Keyshare,
    maybe_seeded_rng,
    message::Message,
    vrf_keyshare::VrfKeyshare,
    vrf_session::{
        decode_messages, encode_message, peer_messages, PartyMessage,
    },
};

#[allow(clippy::large_enum_variant)]
enum Round {
    Init,
    WaitMsg1,
    WaitMsg2,
    Failed,
    Share(dkls23_ll::dkg::Keyshare),
}

struct HardDeriveSessionState {
    state: hard_derivation::State,
    init: MpcDeriveInit,
    threshold: usize,
    party_id: u8,
    participating_party_ids: Vec<u8>,
    round: Round,
}

#[wasm_bindgen]
pub struct HardDeriveSession {
    inner: HardDeriveSessionState,
}

#[wasm_bindgen]
impl HardDeriveSession {
    #[wasm_bindgen(constructor)]
    pub fn new(
        root_keyshare: &Keyshare,
        vrf_keyshare: &VrfKeyshare,
        path: Vec<u8>,
        seed: Option<Vec<u8>>,
    ) -> Result<HardDeriveSession, Error> {
        if root_keyshare.threshold() != vrf_keyshare.threshold() {
            return Err(Error::new(
                "threshold mismatch between root and VRF keyshares",
            ));
        }
        if root_keyshare.participants() != vrf_keyshare.participants() {
            return Err(Error::new(
                "participants mismatch between root and VRF keyshares",
            ));
        }
        if root_keyshare.party_id() != vrf_keyshare.party_id() {
            return Err(Error::new(
                "partyId mismatch between root and VRF keyshares",
            ));
        }

        let init = MpcDeriveInit::with_ristretto_vrf(
            root_keyshare.as_ref().clone(),
            vrf_keyshare.as_inner().clone(),
        );
        let threshold = vrf_keyshare.threshold() as usize;
        let party_id = init.party_id();
        let mut rng = maybe_seeded_rng(seed);

        let state = hard_derivation::State::new(init.clone(), path, &mut rng)
            .map_err(hard_derive_error)?;

        Ok(HardDeriveSession {
            inner: HardDeriveSessionState {
                state,
                init,
                threshold,
                party_id,
                participating_party_ids: vec![],
                round: Round::Init,
            },
        })
    }

    #[wasm_bindgen(js_name = error)]
    pub fn error(&self) -> Option<Error> {
        match &self.inner.round {
            Round::Failed => Some(Error::new("failed")),
            _ => None,
        }
    }

    #[wasm_bindgen(js_name = createFirstMessage)]
    pub fn create_first_message(&mut self) -> Result<Message, Error> {
        match self.inner.round {
            Round::Init => match self.inner.state.generate_msg0() {
                Ok(msg) => {
                    self.inner.round = Round::WaitMsg1;
                    Ok(encode_message(msg))
                }
                Err(err) => {
                    self.inner.round = Round::Failed;
                    Err(hard_derive_error(err))
                }
            },
            Round::Failed => Err(Error::new("failed session")),
            _ => Err(Error::new("invalid state")),
        }
    }

    #[wasm_bindgen(js_name = handleMessages)]
    pub fn handle_messages(
        &mut self,
        messages: Vec<Message>,
        seed: Option<Vec<u8>>,
    ) -> Result<Vec<Message>, Error> {
        if messages.len() != self.inner.threshold {
            return Err(Error::new(&format!(
                "expected {} messages, got {}",
                self.inner.threshold,
                messages.len()
            )));
        }

        let mut senders: Vec<u8> =
            messages.iter().map(|m| m.from_id).collect();
        senders.sort_unstable();
        senders.dedup();
        if senders.len() != self.inner.threshold
            || !senders.contains(&self.inner.party_id)
        {
            return Err(Error::new("invalid message sender set"));
        }

        let mut rng = maybe_seeded_rng(seed);

        match &self.inner.round {
            Round::WaitMsg1 => {
                let decoded = decode_messages::<HardDeriveMsg0>(&messages);
                self.inner.participating_party_ids =
                    party_ids_from_msg0(&decoded);
                let peers = peer_messages(decoded, self.inner.party_id);
                match self.inner.state.handle_msg0(&mut rng, peers, None) {
                    Ok(msg1) => {
                        self.inner.round = Round::WaitMsg2;
                        Ok(vec![encode_message(msg1)])
                    }
                    Err(err) => {
                        self.inner.round = Round::Failed;
                        Err(hard_derive_error(err))
                    }
                }
            }

            Round::WaitMsg2 => {
                let decoded = decode_messages::<HardDeriveMsg1>(&messages);
                match self.inner.state.handle_msg1(decoded) {
                    Ok(output) => {
                        let share = keyshare_after_hard_derive(
                            &self.inner.init,
                            &output,
                            &self.inner.participating_party_ids,
                        );
                        self.inner.round = Round::Share(share);
                        Ok(vec![])
                    }
                    Err(err) => {
                        self.inner.round = Round::Failed;
                        Err(hard_derive_error(err))
                    }
                }
            }

            Round::Failed => Err(Error::new("failed session")),
            _ => Err(Error::new("invalid session state")),
        }
    }

    #[wasm_bindgen(js_name = keyshare)]
    pub fn keyshare(self) -> Result<Keyshare, Error> {
        match self.inner.round {
            Round::Share(share) => Ok(Keyshare::new(share)),
            Round::Failed => Err(Error::new("failed")),
            _ => Err(Error::new("hard-derive-in-progress")),
        }
    }

    #[wasm_bindgen(js_name = isFinished)]
    pub fn is_finished(&self) -> bool {
        matches!(self.inner.round, Round::Share(_) | Round::Failed)
    }
}

fn party_ids_from_msg0(msgs: &[HardDeriveMsg0]) -> Vec<u8> {
    let mut ids: Vec<u8> = msgs.iter().map(|m| m.from_party).collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

impl PartyMessage for HardDeriveMsg0 {
    fn party_id(&self) -> u8 {
        self.from_party
    }
}

impl crate::message::MessageRouting for HardDeriveMsg0 {
    fn src_party_id(&self) -> u8 {
        self.from_party
    }

    fn dst_party_id(&self) -> Option<u8> {
        None
    }
}

impl crate::message::MessageRouting for HardDeriveMsg1 {
    fn src_party_id(&self) -> u8 {
        self.from_party
    }

    fn dst_party_id(&self) -> Option<u8> {
        None
    }
}
