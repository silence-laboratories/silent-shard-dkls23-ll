use digest::Digest;
use k256::{
    elliptic_curve::{group::GroupEncoding, subtle::ConstantTimeEq},
    NonZeroScalar, ProjectivePoint, Secp256k1,
};
use merlin::Transcript;
use sha2::Sha256;

use sl_mpc_mate::{math::birkhoff_coeffs, math::GroupPolynomial, HashBytes, SessionId};
use sl_oblivious::{utils::TranscriptProtocol, zkproofs::DLogProof};

use crate::{constants::*, error::KeygenError};

pub(crate) fn hash_commitment(
    session_id: &SessionId,
    party_id: usize,
    rank: usize,
    x_i: &NonZeroScalar,
    big_f_i_vec: &GroupPolynomial<Secp256k1>,
    r_i: &[u8; 32],
) -> HashBytes {
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
    HashBytes::new(hasher.finalize().into())
}

pub(crate) fn hash_commitment_2(
    session_id: &SessionId,
    chain_code_sid: &SessionId,
    r_i: &[u8; 32],
) -> HashBytes {
    let mut hasher = Sha256::new();
    hasher.update(DKG_LABEL);
    hasher.update(session_id);
    hasher.update(chain_code_sid);
    hasher.update(r_i);
    hasher.update(COMMITMENT_2_LABEL);
    HashBytes::new(hasher.finalize().into())
}

pub(crate) fn get_base_ot_session_id(
    sender_id: usize,
    receiver_id: usize,
    session_id: &SessionId,
) -> SessionId {
    SessionId::new(
        Sha256::new()
            .chain_update(DKG_LABEL)
            .chain_update(session_id)
            .chain_update(b"sender_id")
            .chain_update((sender_id as u64).to_be_bytes())
            .chain_update(b"receiver_id")
            .chain_update((receiver_id as u64).to_be_bytes())
            .chain_update(b"base_ot_session_id")
            .finalize()
            .into(),
    )
}

pub(crate) fn verify_dlog_proofs<'a>(
    final_session_id: &SessionId,
    party_id: usize,
    proofs: &[DLogProof],
    points: impl Iterator<Item = &'a ProjectivePoint>,
) -> Result<(), KeygenError> {
    let mut dlog_transcript =
        Transcript::new_dlog_proof(final_session_id, party_id, &DLOG_PROOF1_LABEL, &DKG_LABEL);

    for (proof, point) in proofs.iter().zip(points) {
        proof
            .verify(point, &ProjectivePoint::GENERATOR, &mut dlog_transcript)
            .then_some(())
            .ok_or(KeygenError::InvalidDLogProof)?;
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
        .iter()
        .zip(betta_vector.iter())
        .fold(ProjectivePoint::IDENTITY, |acc, (point, betta_i)| {
            acc + *point * betta_i
        });

    (public_key == &public_key_point)
        .then_some(())
        .ok_or(KeygenError::PublicKeyMismatch)
}

pub(crate) fn hash_commitment_r_i(
    session_id: &SessionId,
    big_r_i: &ProjectivePoint,
    blind_factor: &[u8; 32],
) -> HashBytes {
    let mut hasher = Sha256::new();
    hasher.update(DSG_LABEL);
    hasher.update(session_id.as_ref());
    hasher.update(big_r_i.to_bytes());
    hasher.update(blind_factor);
    hasher.update(COMMITMENT_LABEL);
    HashBytes::new(hasher.finalize().into())
}

pub(crate) fn verify_commitment_r_i(
    sid: &SessionId,
    big_r_i: &ProjectivePoint,
    blind_factor: &[u8; 32],
    commitment: &HashBytes,
) -> bool {
    let compare_commitment = hash_commitment_r_i(sid, big_r_i, blind_factor);

    commitment.ct_eq(&compare_commitment).into()
}

pub(crate) fn mta_session_id(
    final_session_id: &SessionId,
    sender_id: u8,
    receiver_id: u8,
) -> SessionId {
    let mut h = Sha256::new();
    h.update(DSG_LABEL);
    h.update(final_session_id);
    h.update(b"sender");
    h.update([sender_id]);
    h.update(b"receiver");
    h.update([receiver_id]);
    h.update(PAIRWISE_MTA_LABEL);
    SessionId::new(h.finalize().into())
}

pub(crate) fn get_idx_from_id(current_party_id: u8, for_party_id: u8) -> u8 {
    if for_party_id > current_party_id {
        for_party_id - 1
    } else {
        for_party_id
    }
}
