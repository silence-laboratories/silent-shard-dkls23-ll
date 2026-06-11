// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! MPC-friendly VRF evaluation — thin wrapper over [`sl_mpc_vrf`].
//!
//! Round API matches [`crate::vrf::dkg::State`]: `generate_msg0` → `handle_msg0` → `handle_msg1`.

use rand::{CryptoRng, RngCore};
use sl_mpc_derive::ED25519_VRF_OUTPUT_BITS;
use sl_mpc_vrf::{eval::Context, VrfMsg0, VrfMsg1};

use crate::vrf::dkg::VrfKeyshare;

use super::types::VrfError;

pub use sl_mpc_vrf::VrfOutput;

/// VRF evaluation session (multi-round, t-of-n) over Ristretto.
pub struct State {
    ctx: Context,
    own_msg0: Option<VrfMsg0>,
}

impl State {
    pub fn new<R: RngCore + CryptoRng>(
        keyshare: &VrfKeyshare,
        message: Vec<u8>,
        rng: &mut R,
    ) -> Result<Self, VrfError> {
        Self::new_with_output_bits(
            keyshare,
            message,
            ED25519_VRF_OUTPUT_BITS,
            rng,
        )
    }

    pub fn new_with_output_bits<R: RngCore + CryptoRng>(
        keyshare: &VrfKeyshare,
        message: Vec<u8>,
        output_bits: usize,
        rng: &mut R,
    ) -> Result<Self, VrfError> {
        let ctx = Context::new_with_output_bits(
            keyshare.party_id,
            keyshare.threshold,
            keyshare.total_parties,
            message,
            output_bits,
            *keyshare.shamir_share(),
            keyshare.public_key,
            keyshare.party_public_shares().to_vec(),
            None,
            rng,
        )?;
        Ok(Self {
            ctx,
            own_msg0: None,
        })
    }

    pub fn party_id(&self) -> u8 {
        self.ctx.party_id()
    }

    /// Round 0 outbound: consistency hash and session id contribution.
    pub fn generate_msg0(&mut self) -> Result<VrfMsg0, VrfError> {
        let msg = self.ctx.round0_out()?;
        self.own_msg0 = Some(msg.clone());
        Ok(msg)
    }

    /// Round 0 inbound: collect peer contributions and broadcast partial VRF point.
    ///
    /// When `quorum` is `None`, exactly `threshold` messages are required (including self).
    /// When `quorum` is `Some`, message senders must match that party-id set exactly.
    pub fn handle_msg0<R: RngCore + CryptoRng>(
        &mut self,
        _rng: &mut R,
        peer_msgs: Vec<VrfMsg0>,
        quorum: Option<&[u8]>,
    ) -> Result<VrfMsg1, VrfError> {
        let own = self
            .own_msg0
            .as_ref()
            .ok_or(VrfError::InvalidState)?
            .clone();
        let mut messages = peer_msgs;
        messages.push(own);
        self.ctx.round0_in(messages, quorum)
    }

    /// Round 1 inbound: verify partial points and derive the VRF output.
    pub fn handle_msg1(
        &self,
        messages: Vec<VrfMsg1>,
    ) -> Result<VrfOutput, VrfError> {
        self.ctx.round1_in(messages)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vrf::dkg::test_support::{
        init_states as vrf_dkg_init, vrf_dkg_inner,
    };

    fn init_states(
        keyshares: &[VrfKeyshare],
        message: Vec<u8>,
    ) -> Vec<State> {
        let mut rng = rand::thread_rng();
        keyshares
            .iter()
            .map(|ks| State::new(ks, message.clone(), &mut rng).unwrap())
            .collect()
    }

    fn vrf_eval_inner(
        mut parties: Vec<State>,
        threshold: usize,
    ) -> Vec<VrfOutput> {
        let mut rng = rand::thread_rng();

        let msg0: Vec<VrfMsg0> = parties
            .iter_mut()
            .map(|p| p.generate_msg0().unwrap())
            .collect();

        let msg1: Vec<VrfMsg1> = parties
            .iter_mut()
            .take(threshold)
            .map(|party| {
                let batch: Vec<VrfMsg0> = msg0
                    .iter()
                    .take(threshold)
                    .filter(|msg| msg.from_party != party.party_id())
                    .cloned()
                    .collect();
                party.handle_msg0(&mut rng, batch, None).unwrap()
            })
            .collect();

        parties
            .iter()
            .take(threshold)
            .map(|party| party.handle_msg1(msg1.clone()).unwrap())
            .collect()
    }

    #[test]
    fn vrf_eval_2_of_3() {
        let shares = vrf_dkg_inner(vrf_dkg_init(3, 2));
        let message = b"vrf-eval-test".to_vec();
        let parties = init_states(&shares, message);
        let outputs = vrf_eval_inner(parties, 2);
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].output, outputs[1].output);
    }
}
