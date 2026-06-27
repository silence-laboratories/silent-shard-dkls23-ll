// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Shamir VRF DKG — thin wrapper over [`sl_mpc_vrf::dkg::Context`].

use rand::{CryptoRng, RngCore};
use sl_mpc_vrf::dkg::Context;

pub use sl_mpc_vrf::dkg::{
    Party, VrfKeygenError, VrfKeygenMsg1, VrfKeygenMsg2, VrfKeyshare,
};

/// VRF DKG session (Protocol 12 on Ristretto).
pub struct State {
    ctx: Context,
    own_msg1: Option<VrfKeygenMsg1>,
}

impl State {
    pub fn new<R: RngCore + CryptoRng>(
        party: Party,
        rng: &mut R,
    ) -> Result<Self, VrfKeygenError> {
        Ok(Self {
            ctx: Context::new(party, rng)?,
            own_msg1: None,
        })
    }

    pub fn party_id(&self) -> u8 {
        self.ctx.party_id()
    }

    /// Round 1 outbound: sample polynomial commitments and plaintext P2P shares.
    pub fn generate_msg1<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<VrfKeygenMsg1, VrfKeygenError> {
        let msg = self.ctx.round1_out(rng)?;
        self.own_msg1 = Some(msg);
        Ok(msg)
    }

    /// Round 1 inbound: collect commitments, broadcast opening.
    pub fn handle_msg1<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        peer_msgs: Vec<VrfKeygenMsg1>,
    ) -> Result<VrfKeygenMsg2, VrfKeygenError> {
        let own =
            *self.own_msg1.as_ref().ok_or(VrfKeygenError::InvalidState)?;
        let mut messages = peer_msgs;
        messages.push(own);
        self.ctx.round1_in(rng, messages)
    }

    /// Round 2 inbound: verify openings and derive the VRF key share.
    pub fn handle_msg2(
        &mut self,
        messages: Vec<VrfKeygenMsg2>,
    ) -> Result<VrfKeyshare, VrfKeygenError> {
        self.ctx.round2_in(messages)
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub fn init_states(n: u8, t: u8) -> Vec<State> {
        let mut rng = rand::thread_rng();
        (0..n)
            .map(|party_id| {
                State::new(Party::new(n, t, party_id), &mut rng).unwrap()
            })
            .collect()
    }

    pub fn vrf_dkg_inner(mut parties: Vec<State>) -> Vec<VrfKeyshare> {
        let mut rng = rand::thread_rng();

        let msg1: Vec<VrfKeygenMsg1> = parties
            .iter_mut()
            .map(|p| p.generate_msg1(&mut rng).unwrap())
            .collect();

        let msg2: Vec<VrfKeygenMsg2> = parties
            .iter_mut()
            .map(|party| {
                let batch: Vec<VrfKeygenMsg1> = msg1
                    .iter()
                    .filter(|msg| msg.from_party != party.party_id())
                    .cloned()
                    .collect();
                party.handle_msg1(&mut rng, batch).unwrap()
            })
            .collect();

        parties
            .iter_mut()
            .map(|party| party.handle_msg2(msg2.clone()).unwrap())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{init_states, vrf_dkg_inner};
    use super::*;
    use curve25519_dalek::RistrettoPoint;

    fn assert_shared_vrf_state(shares: &[VrfKeyshare]) {
        let reference = &shares[0];
        let pk = reference.public_key();
        let chain = reference.root_chain_code;
        let key_id = reference.key_id;
        let final_sid = reference.final_session_id;
        let additive_shares = reference.party_public_shares();

        for share in &shares[1..] {
            assert_eq!(share.public_key(), pk);
            assert_eq!(share.root_chain_code, chain);
            assert_eq!(share.key_id, key_id);
            assert_eq!(share.final_session_id, final_sid);
            assert_eq!(share.party_public_shares(), additive_shares);
        }

        let sum: RistrettoPoint = additive_shares.iter().sum();
        assert_eq!(sum, *pk);
    }

    #[test]
    fn vrf_dkg_3_out_of_3() {
        let shares = vrf_dkg_inner(init_states(3, 3));
        assert_eq!(shares.len(), 3);
        assert_shared_vrf_state(&shares);
    }

    #[test]
    fn vrf_dkg_2_out_of_3() {
        let shares = vrf_dkg_inner(init_states(3, 2));
        assert_eq!(shares.len(), 3);
        assert_shared_vrf_state(&shares);
    }
}
