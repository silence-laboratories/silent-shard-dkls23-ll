// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! [`HardDeriveRoot`] for DKLS23 secp256k1 root keyshares.

use k256::{
    elliptic_curve::group::prime::PrimeCurveAffine, NonZeroScalar,
    ProjectivePoint, Scalar,
};
use sl_mpc_derive::{
    hard_derive::{HardDeriveError, HardDeriveOutput},
    HardDeriveRoot, HardDeriveSigning,
};

use crate::{dkg::Keyshare, dsg::get_lagrange_coeff};

/// Signing root adapter: DKLS keyshare + derived additive public shares K_j = λ_j · S_j.
pub struct DklsHardDeriveRoot {
    keyshare: Keyshare,
    public_key: ProjectivePoint,
    party_public_shares: Vec<ProjectivePoint>,
}

impl DklsHardDeriveRoot {
    pub fn new(keyshare: Keyshare) -> Self {
        let public_key = keyshare.public_key.to_curve();
        let party_public_shares = compute_party_public_shares(&keyshare);
        Self {
            keyshare,
            public_key,
            party_public_shares,
        }
    }
}

impl HardDeriveRoot for DklsHardDeriveRoot {
    type Point = ProjectivePoint;

    fn party_id(&self) -> u8 {
        self.keyshare.party_id
    }

    fn threshold(&self) -> u8 {
        self.keyshare.threshold
    }

    fn total_parties(&self) -> u8 {
        self.keyshare.total_parties
    }

    fn public_key(&self) -> &ProjectivePoint {
        &self.public_key
    }

    fn party_public_shares(&self) -> &[ProjectivePoint] {
        &self.party_public_shares
    }

    fn scalar_share_for_participants(
        &self,
        participating_party_ids: &[u8],
    ) -> Scalar {
        get_lagrange_coeff(
            &self.keyshare,
            participating_party_ids.iter().copied(),
        ) * self.keyshare.s_i
    }
}

fn compute_party_public_shares(ks: &Keyshare) -> Vec<ProjectivePoint> {
    (0..ks.total_parties)
        .map(|j| {
            let lambda_j =
                lagrange_coeff_at_party(&ks.x_i_list, j, 0..ks.total_parties);
            ks.big_s_list[j as usize].to_curve() * lambda_j
        })
        .collect()
}

pub(crate) fn lagrange_coeff_at_party(
    x_i_list: &[NonZeroScalar],
    party_id: u8,
    parties: impl Iterator<Item = u8>,
) -> Scalar {
    let mut coeff = Scalar::ONE;
    let x_i = &x_i_list[party_id as usize] as &Scalar;
    for other in parties {
        if other == party_id {
            continue;
        }
        let x_j = &x_i_list[other as usize] as &Scalar;
        let sub = x_j - x_i;
        coeff *= x_j * &sub.invert().unwrap();
    }
    coeff
}

fn dkls_participant_public_share(
    keyshare: &Keyshare,
    full_share: &ProjectivePoint,
    party_id: u8,
    participating: impl Iterator<Item = u8> + Clone,
) -> ProjectivePoint {
    let full_coeff = lagrange_coeff_at_party(
        &keyshare.x_i_list,
        party_id,
        0..keyshare.total_parties,
    );
    let part_coeff =
        lagrange_coeff_at_party(&keyshare.x_i_list, party_id, participating);
    *full_share * (part_coeff * full_coeff.invert().unwrap())
}

/// DKLS hard-derive tweak using `x_i_list` Lagrange (not Shamir `party_id + 1`).
pub fn apply_hard_derive_dkls(
    root: &DklsHardDeriveRoot,
    vrf_output_y: &[u8],
    threshold: u8,
    participating_party_ids: &[u8],
) -> Result<HardDeriveOutput<ProjectivePoint>, HardDeriveError> {
    if threshold == 0 {
        return Err(HardDeriveError::InvalidThreshold);
    }
    if participating_party_ids.len() < threshold as usize {
        return Err(HardDeriveError::InvalidThreshold);
    }

    let (delta_prime, chain_code) =
        HardDeriveOutput::<ProjectivePoint>::split_vrf_output(vrf_output_y)?;
    let delta = ProjectivePoint::delta_from_vrf(&delta_prime);

    let participant_count =
        Scalar::from(participating_party_ids.len() as u64);
    let delta_over_t = delta * participant_count.invert().unwrap();

    let delta_g = ProjectivePoint::GENERATOR * delta;
    let delta_over_t_g = ProjectivePoint::GENERATOR * delta_over_t;

    let public_key_prime = *root.public_key() + delta_g;

    let total_parties = root.total_parties();
    let mut party_public_shares_prime = root.party_public_shares().to_vec();
    let public_shares_len = party_public_shares_prime.len();
    let mut seen_participants = vec![false; public_shares_len];
    for &pid in participating_party_ids {
        let pid_index = pid as usize;
        if pid >= total_parties || pid_index >= public_shares_len {
            return Err(HardDeriveError::InvalidParticipatingPartyId {
                pid,
                total_parties,
                public_shares_len,
            });
        }
        if seen_participants[pid_index] {
            return Err(HardDeriveError::DuplicateParticipatingPartyId {
                pid,
            });
        }
        seen_participants[pid_index] = true;
    }
    for &pid in participating_party_ids {
        let pid_index = pid as usize;
        let k_j = dkls_participant_public_share(
            &root.keyshare,
            &party_public_shares_prime[pid_index],
            pid,
            participating_party_ids.iter().copied(),
        );
        party_public_shares_prime[pid_index] = k_j + delta_over_t_g;
    }

    let mut xi_prime =
        root.scalar_share_for_participants(participating_party_ids);
    if participating_party_ids.contains(&root.party_id()) {
        xi_prime += delta_over_t;
    }

    Ok(HardDeriveOutput {
        xi_prime,
        public_key_prime,
        party_public_shares_prime,
        chain_code,
    })
}
