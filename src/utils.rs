// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::{
    marker::PhantomData,
    mem,
    ops::{Deref, DerefMut},
};

use bytemuck::{AnyBitPattern, NoUninit};
use k256::{
    elliptic_curve::{
        group::GroupEncoding,
        subtle::{Choice, ConstantTimeEq},
    },
    NonZeroScalar, ProjectivePoint, Secp256k1,
};
use merlin::Transcript;
use sha2::{Digest, Sha256};

use sl_mpc_mate::{math::birkhoff_coeffs, math::GroupPolynomial};
use sl_oblivious::{utils::TranscriptProtocol, zkproofs::DLogProof};

use crate::{constants::*, error::KeygenError};

pub struct ZS<T: AnyBitPattern + NoUninit> {
    buffer: Vec<u8>,
    marker: PhantomData<T>,
}

pub(crate) fn hash_commitment(
    session_id: &[u8; 32],
    party_id: usize,
    rank: usize,
    x_i: &NonZeroScalar,
    big_f_i_vec: &GroupPolynomial<Secp256k1>,
    r_i: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DKG_LABEL);
    hasher.update(session_id);
    hasher.update((party_id as u64).to_be_bytes());
    hasher.update((rank as u64).to_be_bytes());
    hasher.update(x_i.to_bytes());
    for point in big_f_i_vec.points() {
        hasher.update(point.to_bytes());
    }
    hasher.update(r_i);
    hasher.update(COMMITMENT_1_LABEL);
    hasher.finalize().into()
}

pub(crate) fn hash_commitment_2(
    session_id: &[u8; 32],
    chain_code_sid: &[u8; 32],
    r_i: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DKG_LABEL);
    hasher.update(session_id);
    hasher.update(chain_code_sid);
    hasher.update(r_i);
    hasher.update(COMMITMENT_2_LABEL);
    hasher.finalize().into()
}

pub(crate) fn get_base_ot_session_id(
    sender_id: usize,
    receiver_id: usize,
    session_id: &[u8; 32],
) -> [u8; 32] {
    Sha256::new()
        .chain_update(DKG_LABEL)
        .chain_update(session_id)
        .chain_update(b"sender_id")
        .chain_update((sender_id as u64).to_be_bytes())
        .chain_update(b"receiver_id")
        .chain_update((receiver_id as u64).to_be_bytes())
        .chain_update(b"base_ot_session_id")
        .finalize()
        .into()
}

pub(crate) fn get_all_but_one_session_id(
    sender_id: usize,
    receiver_id: usize,
    session_id: &[u8],
) -> [u8; 32] {
    Sha256::new()
        .chain_update(DKG_LABEL)
        .chain_update(session_id)
        .chain_update(b"sender_id")
        .chain_update((sender_id as u64).to_be_bytes())
        .chain_update(b"receiver_id")
        .chain_update((receiver_id as u64).to_be_bytes())
        .chain_update(b"all_but_one_session_id")
        .finalize()
        .into()
}

pub(crate) fn verify_dlog_proofs<'a>(
    final_session_id: &[u8; 32],
    party_id: usize,
    proofs: &[DLogProof],
    points: impl Iterator<Item = &'a ProjectivePoint>,
) -> Result<(), KeygenError> {
    let mut dlog_transcript = Transcript::new_dlog_proof(
        final_session_id,
        party_id,
        &DLOG_PROOF1_LABEL,
        &DKG_LABEL,
    );

    let mut ok = Choice::from(1);

    for (proof, point) in proofs.iter().zip(points) {
        ok &= proof.verify(
            point,
            &ProjectivePoint::GENERATOR,
            &mut dlog_transcript,
        );
    }

    if ok.unwrap_u8() == 0 {
        return Err(KeygenError::InvalidDLogProof);
    }

    Ok(())
}

pub(crate) fn check_secret_recovery(
    x_i_list: &[NonZeroScalar],
    rank_list: &[u8],
    big_s_list: &[ProjectivePoint],
    public_key: &ProjectivePoint,
) -> Result<(), KeygenError> {
    // Checking if secret recovery works
    let mut party_params_list = x_i_list
        .iter()
        .zip(rank_list)
        .zip(big_s_list)
        .collect::<Vec<((&NonZeroScalar, &u8), &ProjectivePoint)>>();

    party_params_list.sort_by_key(|((_, n_i), _)| *n_i);

    let params = party_params_list
        .iter()
        .map(|((x_i, n_i), _)| (**x_i, **n_i as usize))
        .collect::<Vec<_>>();

    let sorted_big_s_list = party_params_list
        .iter()
        .map(|((_, _), big_s_i)| *big_s_i)
        .collect::<Vec<_>>();

    let betta_vector = birkhoff_coeffs(params.as_slice());
    let public_key_point = sorted_big_s_list
        .into_iter()
        .zip(&betta_vector)
        .fold(ProjectivePoint::IDENTITY, |acc, (point, betta_i)| {
            acc + point * betta_i
        });

    (public_key == &public_key_point)
        .then_some(())
        .ok_or(KeygenError::PublicKeyMismatch)
}

pub(crate) fn hash_commitment_r_i(
    session_id: &[u8],
    big_r_i: &ProjectivePoint,
    blind_factor: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DSG_LABEL);
    hasher.update(session_id.as_ref());
    hasher.update(big_r_i.to_bytes());
    hasher.update(blind_factor);
    hasher.update(COMMITMENT_LABEL);
    hasher.finalize().into()
}

pub(crate) fn verify_commitment_r_i(
    sid: &[u8],
    big_r_i: &ProjectivePoint,
    blind_factor: &[u8; 32],
    commitment: &[u8; 32],
) -> bool {
    let compare_commitment = hash_commitment_r_i(sid, big_r_i, blind_factor);

    commitment.ct_eq(&compare_commitment).into()
}

pub(crate) fn mta_session_id(
    final_session_id: &[u8],
    sender_id: u8,
    receiver_id: u8,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DSG_LABEL);
    h.update(final_session_id);
    h.update(b"sender");
    h.update([sender_id]);
    h.update(b"receiver");
    h.update([receiver_id]);
    h.update(PAIRWISE_MTA_LABEL);
    h.finalize().into()
}

pub(crate) fn get_idx_from_id(current_party_id: u8, for_party_id: u8) -> u8 {
    if for_party_id > current_party_id {
        for_party_id - 1
    } else {
        for_party_id
    }
}

impl<T> From<Box<T>> for ZS<T>
where
    T: AnyBitPattern + NoUninit,
{
    fn from(b: Box<T>) -> Self {
        assert!(mem::align_of::<T>() == 1);

        let s = mem::size_of::<T>();
        let r = Box::into_raw(b);
        let v = unsafe { Vec::<u8>::from_raw_parts(r as *mut u8, s, s) };

        Self {
            buffer: v,
            marker: PhantomData,
        }
    }
}

impl<T> Default for ZS<T>
where
    T: AnyBitPattern + NoUninit,
{
    fn default() -> Self {
        Self {
            buffer: vec![0u8; mem::size_of::<T>()],
            marker: PhantomData,
        }
    }
}

impl<T> Deref for ZS<T>
where
    T: AnyBitPattern + NoUninit,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        bytemuck::from_bytes(&self.buffer)
    }
}

impl<T> DerefMut for ZS<T>
where
    T: AnyBitPattern + NoUninit,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        bytemuck::from_bytes_mut(&mut self.buffer)
    }
}

impl<T> Clone for ZS<T>
where
    T: AnyBitPattern + NoUninit,
{
    fn clone(&self) -> Self {
        Self {
            buffer: self.buffer.clone(),
            marker: PhantomData,
        }
    }
}

impl<T> serde::Serialize for ZS<T>
where
    T: AnyBitPattern + NoUninit,
{
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        self.buffer.serialize(serializer)
    }
}

impl<'de, T> serde::Deserialize<'de> for ZS<T>
where
    T: AnyBitPattern + NoUninit,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let buffer = <Vec<u8>>::deserialize(deserializer)?;

        if buffer.len() != mem::size_of::<T>() {
            return Err(serde::de::Error::invalid_length(
                buffer.len(),
                &"bytes",
            ));
        }

        Ok(Self {
            buffer,
            marker: PhantomData,
        })
    }
}
