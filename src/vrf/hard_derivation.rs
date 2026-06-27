// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! VRF orchestration for MPC hard derivation (Ristretto VRF + DKLS23 k256 root).
//!
//! Round API matches [`crate::vrf::dkg::State`]: `generate_msg0` → `handle_msg0` → `handle_msg1`.

use k256::{AffinePoint, ProjectivePoint, Scalar};
use rand::{CryptoRng, RngCore};
use sl_mpc_derive::{
    hard_derive::{
        HardDeriveError as HardDeriveTweakError, HardDeriveOutput,
    },
    HARD_DERIVE_VRF_OUTPUT_BITS,
};
use thiserror::Error;

use crate::{dkg::Keyshare, dsg::get_lagrange_coeff, vrf::dkg::VrfKeyshare};

use super::{
    eval,
    hard_derive_root::{
        apply_hard_derive_dkls, lagrange_coeff_at_party, DklsHardDeriveRoot,
    },
    messages::VrfMsg1,
    types::VrfError,
};

pub use super::messages::VrfMsg0 as HardDeriveMsg0;
pub use sl_mpc_derive::hard_derive::HardDeriveOutput as HardDeriveOutputK256;
pub type HardDeriveMsg1 = VrfMsg1;

/// Inputs: DKLS23 root keyshare + Ristretto VRF DKG keyshare.
#[derive(Clone)]
pub struct MpcDeriveInit {
    pub vrf_keyshare: VrfKeyshare,
    pub root_keyshare: Keyshare,
}

#[derive(Error, Debug)]
pub enum HardDeriveError {
    #[error(transparent)]
    Derive(#[from] HardDeriveTweakError),
    #[error(transparent)]
    Vrf(#[from] VrfError),
}

/// Hard-derivation session: MPC VRF eval then local tweak of the DKLS root keyshare.
pub struct State {
    init: MpcDeriveInit,
    vrf: eval::State,
}

impl MpcDeriveInit {
    pub fn with_ristretto_vrf(
        root_keyshare: Keyshare,
        vrf_keyshare: VrfKeyshare,
    ) -> Self {
        Self {
            vrf_keyshare,
            root_keyshare,
        }
    }

    pub fn party_id(&self) -> u8 {
        self.vrf_keyshare.party_id
    }
}

impl State {
    pub fn new<R: RngCore + CryptoRng>(
        init: MpcDeriveInit,
        path: Vec<u8>,
        rng: &mut R,
    ) -> Result<Self, HardDeriveError> {
        let vrf = eval::State::new_with_output_bits(
            &init.vrf_keyshare,
            path,
            HARD_DERIVE_VRF_OUTPUT_BITS,
            rng,
        )?;
        Ok(Self { init, vrf })
    }

    pub fn party_id(&self) -> u8 {
        self.vrf.party_id()
    }

    /// Round 0 outbound.
    pub fn generate_msg0(
        &mut self,
    ) -> Result<HardDeriveMsg0, HardDeriveError> {
        self.vrf.generate_msg0().map_err(HardDeriveError::Vrf)
    }

    /// Round 0 inbound.
    pub fn handle_msg0<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        peer_msgs: Vec<HardDeriveMsg0>,
        quorum: Option<&[u8]>,
    ) -> Result<HardDeriveMsg1, HardDeriveError> {
        self.vrf
            .handle_msg0(rng, peer_msgs, quorum)
            .map_err(HardDeriveError::Vrf)
    }

    /// Round 1 inbound: finish VRF eval and apply the hard-derive tweak.
    pub fn handle_msg1(
        &self,
        messages: Vec<HardDeriveMsg1>,
    ) -> Result<HardDeriveOutput<ProjectivePoint>, HardDeriveError> {
        let vrf_out = self.vrf.handle_msg1(messages)?;
        let threshold = self.init.vrf_keyshare.threshold;
        let root = DklsHardDeriveRoot::new(self.init.root_keyshare.clone());
        apply_hard_derive_dkls(
            &root,
            &vrf_out.output,
            threshold,
            &vrf_out.pid_list,
        )
        .map_err(HardDeriveError::Derive)
    }
}

/// Build a DKLS [`Keyshare`] from hard-derivation output (same participant set as VRF).
pub fn keyshare_after_hard_derive(
    init: &MpcDeriveInit,
    output: &HardDeriveOutput<ProjectivePoint>,
    participating_party_ids: &[u8],
) -> Keyshare {
    let root = &init.root_keyshare;
    let lagrange_self =
        get_lagrange_coeff(root, participating_party_ids.iter().copied());
    let s_i_new = output.xi_prime * lagrange_self.invert().unwrap();

    let big_s_list: Vec<AffinePoint> = (0..root.total_parties)
        .map(|j| {
            if participating_party_ids.contains(&j) {
                let lambda_j = full_lagrange_at_party(root, j);
                let big_s_j = output.party_public_shares_prime[j as usize]
                    * lambda_j.invert().unwrap();
                AffinePoint::from(big_s_j)
            } else {
                root.big_s_list[j as usize]
            }
        })
        .collect();

    let public_key = AffinePoint::from(output.public_key_prime);
    let root_chain_code = output.chain_code;

    Keyshare {
        total_parties: root.total_parties,
        threshold: root.threshold,
        rank_list: root.rank_list.clone(),
        party_id: root.party_id,
        public_key,
        root_chain_code,
        final_session_id: root.final_session_id,
        seed_ot_receivers: root.seed_ot_receivers.clone(),
        seed_ot_senders: root.seed_ot_senders.clone(),
        sent_seed_list: root.sent_seed_list.clone(),
        rec_seed_list: root.rec_seed_list.clone(),
        s_i: s_i_new,
        big_s_list,
        x_i_list: root.x_i_list.clone(),
    }
}

fn full_lagrange_at_party(root: &Keyshare, party_id: u8) -> Scalar {
    lagrange_coeff_at_party(&root.x_i_list, party_id, 0..root.total_parties)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use derivation_path::DerivationPath;
    use k256::{
        ecdsa::{
            signature::hazmat::PrehashVerifier, Signature, VerifyingKey,
        },
        elliptic_curve::{group::prime::PrimeCurveAffine, PublicKey},
    };

    const TEST_HASH: [u8; 32] = [255u8; 32];

    use super::*;
    use crate::{
        dkg::tests::dkg,
        dsg::{
            combine_signatures, create_partial_signature, derive_with_offset,
            State as SignState,
        },
        vrf::dkg::test_support::{
            init_states as vrf_init_states, vrf_dkg_inner,
        },
    };

    fn init_states(inits: &[MpcDeriveInit], path: Vec<u8>) -> Vec<State> {
        let mut rng = rand::thread_rng();
        inits
            .iter()
            .cloned()
            .map(|init| State::new(init, path.clone(), &mut rng).unwrap())
            .collect()
    }

    fn hard_derive_inner(
        mut parties: Vec<State>,
        threshold: usize,
    ) -> Vec<HardDeriveOutput<ProjectivePoint>> {
        let mut rng = rand::thread_rng();

        let msg0: Vec<HardDeriveMsg0> = parties
            .iter_mut()
            .map(|p| p.generate_msg0().unwrap())
            .collect();

        let msg1: Vec<HardDeriveMsg1> = parties
            .iter_mut()
            .take(threshold)
            .map(|party| {
                let batch: Vec<HardDeriveMsg0> = msg0
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

    fn mpc_derive_init(n: u8, t: u8) -> Vec<MpcDeriveInit> {
        let vrf_shares = vrf_dkg_inner(vrf_init_states(n, t));
        let root_shares = dkg(n, t);
        vrf_shares
            .into_iter()
            .zip(root_shares)
            .map(|(vrf, root)| MpcDeriveInit::with_ristretto_vrf(root, vrf))
            .collect()
    }

    fn run_hard_derive(
        inits: Vec<MpcDeriveInit>,
        path: &[u8],
        threshold: usize,
    ) -> Vec<HardDeriveOutput<ProjectivePoint>> {
        hard_derive_inner(init_states(&inits, path.to_vec()), threshold)
    }

    fn sign_with_derived(shares: &[Keyshare], path: &str) -> Signature {
        let mut rng = rand::thread_rng();
        let chain_path = DerivationPath::from_str(path).unwrap();
        let mut parties = shares
            .iter()
            .map(|s| {
                SignState::new(&mut rng, s.clone(), &chain_path).unwrap()
            })
            .collect::<Vec<_>>();

        let msg1: Vec<_> =
            parties.iter_mut().map(|p| p.generate_msg1()).collect();
        let msg2 = parties.iter_mut().fold(vec![], |mut acc, party| {
            let batch: Vec<_> = msg1
                .iter()
                .filter(|m| m.from_id != party.keyshare.party_id)
                .cloned()
                .collect();
            acc.extend(party.handle_msg1(&mut rng, batch).unwrap());
            acc
        });
        let msg3 = parties.iter_mut().fold(vec![], |mut acc, party| {
            let batch: Vec<_> = msg2
                .iter()
                .filter(|m| m.to_id == party.keyshare.party_id)
                .cloned()
                .collect();
            acc.extend(party.handle_msg2(&mut rng, batch).unwrap());
            acc
        });
        let pre_signs: Vec<_> = parties
            .iter_mut()
            .map(|party| {
                let batch: Vec<_> = msg3
                    .iter()
                    .filter(|m| m.to_id == party.keyshare.party_id)
                    .cloned()
                    .collect();
                party.handle_msg3(batch).unwrap()
            })
            .collect();

        let hash = TEST_HASH;
        let (partials, msg4): (Vec<_>, Vec<_>) = pre_signs
            .into_iter()
            .map(|pre| create_partial_signature(pre, hash))
            .unzip();

        let partial = partials.into_iter().next().unwrap();
        let batch: Vec<_> = msg4
            .iter()
            .filter(|m| m.from_id != partial.party_id)
            .cloned()
            .collect();
        combine_signatures(partial, batch).unwrap()
    }

    #[test]
    fn dkg_sign_baseline_m_path() {
        let shares = dkg(2, 2);
        let soft_path = DerivationPath::from_str("m/0/1").unwrap();
        let (_, expected_pk) = derive_with_offset(
            &shares[0].public_key.to_curve(),
            &shares[0].root_chain_code,
            &soft_path,
        )
        .unwrap();
        let sig = sign_with_derived(&shares, "m/0/1");
        let vk = VerifyingKey::from(
            PublicKey::from_affine(AffinePoint::from(expected_pk)).unwrap(),
        );
        vk.verify_prehash(&TEST_HASH, &sig).unwrap();
    }

    #[test]
    fn mpc_hard_derive_2_of_2() {
        let inits = mpc_derive_init(2, 2);
        let path = b"m/44'/0'/0'";
        let participating = vec![0u8, 1u8];
        let outputs = run_hard_derive(inits.clone(), path, 2);
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].public_key_prime, outputs[1].public_key_prime);

        let derived: Vec<_> = inits
            .into_iter()
            .zip(outputs)
            .map(|(init, out)| {
                keyshare_after_hard_derive(&init, &out, &participating)
            })
            .collect();

        let soft_path = DerivationPath::from_str("m/0/1").unwrap();
        let (_, expected_pk) = derive_with_offset(
            &derived[0].public_key.to_curve(),
            &derived[0].root_chain_code,
            &soft_path,
        )
        .unwrap();

        let sig = sign_with_derived(&derived, "m/0/1");
        let vk = VerifyingKey::from(
            PublicKey::from_affine(AffinePoint::from(expected_pk)).unwrap(),
        );
        vk.verify_prehash(&TEST_HASH, &sig).unwrap();
    }

    #[test]
    fn mpc_hard_derive_2_of_3() {
        let inits = mpc_derive_init(3, 2);
        let path = b"m/44'/0'/0'";
        let q_root = inits[0].root_keyshare.public_key.to_curve();
        let participating = vec![0u8, 1u8];

        let outputs = run_hard_derive(inits.clone(), path, 2);
        assert_eq!(outputs.len(), 2);

        let q_prime = outputs[0].public_key_prime;
        for out in &outputs[1..] {
            assert_eq!(out.public_key_prime, q_prime);
            assert_eq!(out.chain_code, outputs[0].chain_code);
            assert_eq!(
                out.party_public_shares_prime,
                outputs[0].party_public_shares_prime
            );
        }
        assert_ne!(q_prime, q_root);

        let mut sum_active = ProjectivePoint::IDENTITY;
        for pid in &participating {
            sum_active += outputs[0].party_public_shares_prime[*pid as usize];
        }
        assert_eq!(sum_active, q_prime);

        let derived: Vec<_> = inits
            .iter()
            .take(2)
            .zip(&outputs)
            .map(|(init, out)| {
                keyshare_after_hard_derive(init, out, &participating)
            })
            .collect();

        for (out, ks) in outputs.iter().zip(&derived) {
            let additive =
                get_lagrange_coeff(ks, participating.iter().copied())
                    * ks.s_i;
            assert_eq!(additive, out.xi_prime);
        }

        let soft_path = DerivationPath::from_str("m/0/1").unwrap();
        let mut expected_soft_pk = None;
        for ks in &derived {
            let (_, soft_pk) = derive_with_offset(
                &ks.public_key.to_curve(),
                &ks.root_chain_code,
                &soft_path,
            )
            .unwrap();
            if let Some(expected) = expected_soft_pk {
                assert_eq!(expected, soft_pk);
            } else {
                expected_soft_pk = Some(soft_pk);
            }
        }

        let sig = sign_with_derived(&derived, "m/0/1");
        let vk = VerifyingKey::from(
            PublicKey::from_affine(AffinePoint::from(
                expected_soft_pk.unwrap(),
            ))
            .unwrap(),
        );
        vk.verify_prehash(&TEST_HASH, &sig).unwrap();
    }
}
