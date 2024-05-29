// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! The structs and functions to compute the DKG for DKLS23
//! Structs with pub from_id: u8, pub to_id: u8, fields are intended to be send in point to point fashion
//! while Structs only with  from_id: u8 are distributed to each party
//! Proper validation of each input at each round is needed when deployed in a real world.
#![allow(missing_docs)]
use std::collections::HashSet;

use k256::{
    elliptic_curve::{
        group::prime::PrimeCurveAffine, subtle::ConstantTimeEq, Group,
    },
    AffinePoint, FieldBytes, NonZeroScalar, ProjectivePoint, Scalar,
    Secp256k1,
};
use merlin::Transcript;
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use sl_mpc_mate::math::{
    feldman_verify, polynomial_coeff_multipliers, GroupPolynomial, Polynomial,
};

use sl_oblivious::{
    endemic_ot::EndemicOTMsg2,
    endemic_ot::{EndemicOTMsg1, EndemicOTReceiver, EndemicOTSender},
    soft_spoken::{build_pprf, eval_pprf},
    soft_spoken::{PPRFOutput, ReceiverOTSeed, SenderOTSeed},
    utils::TranscriptProtocol,
    zkproofs::DLogProof,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{constants::*, pairs::*, utils::*};

pub use crate::error::KeygenError;

///
pub struct Party {
    pub ranks: Vec<u8>, // ranks of parties
    pub t: u8,
    pub party_id: u8,
}

///
#[derive(Clone, Serialize, Deserialize)]
pub struct KeygenMsg1 {
    pub from_id: u8,
    session_id: [u8; 32],
    commitment: [u8; 32],
    x_i: NonZeroScalar,
}

/// P2P, encrypted message.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct KeygenMsg2 {
    pub from_id: u8,
    pub to_id: u8,

    // P2P part
    ot: ZS<EndemicOTMsg1>,

    // broadcast part, does not contain secret material
    #[zeroize(skip)]
    big_f_i_vec: GroupPolynomial<Secp256k1>,
    #[zeroize(skip)]
    r_i: [u8; 32],
    #[zeroize(skip)]
    dlog_proofs: Vec<DLogProof>,
}

///
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct KeygenMsg3 {
    pub from_id: u8,
    pub to_id: u8,

    /// Participants Fi values
    /// in original protocol, this field is part
    /// of a boradcast message and its content is
    /// not a secret meterial.
    #[zeroize(skip)]
    big_f_vec: GroupPolynomial<Secp256k1>,

    ///
    d_i: Scalar,

    /// base OT msg 2
    base_ot_msg2: ZS<EndemicOTMsg2>,

    /// pprf outputs
    pprf_output: ZS<PPRFOutput>,

    /// seed_i_j values
    seed_i_j: Option<[u8; 32]>,

    /// chain_code_sid
    chain_code_sid: [u8; 32],

    /// Random 32 bytes
    r_i_2: [u8; 32],
}

///
#[derive(Clone, Serialize, Deserialize)]
pub struct KeygenMsg4 {
    pub from_id: u8,

    public_key: AffinePoint,
    big_s_i: AffinePoint,
    proof: DLogProof,
}

/// Keyshare of a party.
#[allow(missing_docs)]
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Keyshare {
    /// Total number of parties
    pub total_parties: u8,
    /// Threshold value
    pub threshold: u8,
    /// Rank of each party
    pub rank_list: Vec<u8>,
    /// Party Id of the sender
    pub party_id: u8,
    /// Public key of the generated key.
    pub public_key: AffinePoint,
    /// Root chain code (used to derive child public keys)
    pub root_chain_code: [u8; 32],

    pub(crate) final_session_id: [u8; 32],
    pub(crate) seed_ot_receivers: Vec<ZS<ReceiverOTSeed>>,
    pub(crate) seed_ot_senders: Vec<ZS<SenderOTSeed>>,
    pub(crate) sent_seed_list: Vec<[u8; 32]>,
    pub(crate) rec_seed_list: Vec<[u8; 32]>,
    pub(crate) s_i: Scalar,
    pub(crate) big_s_list: Vec<AffinePoint>,
    pub(crate) x_i_list: Vec<NonZeroScalar>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[allow(missing_docs)]
pub struct State {
    party_id: u8,
    ranks: Vec<u8>,
    t: u8,
    key_refresh: bool,

    pub final_session_id: [u8; 32],
    #[zeroize(skip)] // FIXME we must zeroize this field
    pub polynomial: Polynomial<Secp256k1>,
    #[zeroize(skip)]
    pub big_f_vec: GroupPolynomial<Secp256k1>,
    pub chain_code_sids: Pairs<[u8; 32]>,
    pub root_chain_code: [u8; 32],
    pub r_i_2: [u8; 32],
    pub commitment_list: Pairs<[u8; 32]>,
    pub sid_i_list: Pairs<[u8; 32]>,
    pub x_i_list: Pairs<NonZeroScalar>,
    pub r_i_list: Pairs<[u8; 32]>,
    pub d_i_list: Pairs<Scalar>,
    #[zeroize(skip)]
    pub big_f_i_vecs: Pairs<GroupPolynomial<Secp256k1>>,
    #[zeroize(skip)]
    pub dlog_proofs_i_list: Pairs<Vec<DLogProof>>,
    pub s_i: Scalar,
    pub seed_ot_receivers: Pairs<ZS<ReceiverOTSeed>>,
    pub seed_ot_senders: Pairs<ZS<SenderOTSeed>>,
    pub rec_seed_list: Pairs<[u8; 32]>,
    pub seed_i_j_list: Pairs<[u8; 32]>,
    #[zeroize(skip)] // FIXME we must zeroize this field
    pub base_ot_receivers: Pairs<EndemicOTReceiver>,
}

fn other_parties(
    ranks: &[u8],
    party_id: u8,
) -> impl Iterator<Item = u8> + '_ {
    ranks
        .iter()
        .enumerate()
        .map(|(p, _)| p as u8)
        .filter(move |p| *p != party_id)
}

impl Party {
    /// Return a party definition with zero ranks.
    pub fn new(n: usize, t: usize, party_id: usize) -> Self {
        debug_assert!(t > 1 && t <= n);
        Self {
            ranks: vec![0; n],
            t: t as u8,
            party_id: party_id as _,
        }
    }
}

impl State {
    ///
    pub fn new<R: RngCore + CryptoRng>(
        party: Party,
        rng: &mut R,
        x_i: Option<&NonZeroScalar>,
    ) -> Self {
        let Party { party_id, ranks, t } = party;
        let key_refresh = x_i.is_some();

        // currently we support only zero ranks in this impl.
        assert!(ranks.iter().all(|&r| r == 0));

        let r_i = rng.gen();
        let session_id = rng.gen();

        // u_i_k
        let mut polynomial = Polynomial::random(rng, t as usize - 1);
        if key_refresh {
            polynomial.reset_contant();
        }

        let x_i = match x_i {
            Some(x_i) => *x_i,
            None => NonZeroScalar::random(rng),
        };

        let big_f_i_vec = polynomial.commit();

        let commitment = hash_commitment(
            &session_id,
            party_id as usize,
            ranks[party_id as usize] as usize,
            &x_i,
            &big_f_i_vec,
            &r_i,
        );

        let big_f_i_vec = polynomial.commit();
        let d_i =
            polynomial.derivative_at(ranks[party_id as usize] as usize, &x_i);

        Self {
            party_id,
            ranks,
            t,
            key_refresh,
            polynomial,

            r_i_2: rng.gen(),
            sid_i_list: Pairs::new_with_item(party_id, session_id),
            x_i_list: Pairs::new_with_item(party_id, x_i),
            r_i_list: Pairs::new_with_item(party_id, r_i),
            d_i_list: Pairs::new_with_item(party_id, d_i),
            commitment_list: Pairs::new_with_item(party_id, commitment),
            chain_code_sids: Pairs::new_with_item(party_id, rng.gen()),
            root_chain_code: [0; 32],
            big_f_vec: GroupPolynomial::identity(t as usize),
            big_f_i_vecs: Pairs::new_with_item(party_id, big_f_i_vec.clone()),
            final_session_id: [0; 32],
            base_ot_receivers: Pairs::new(),
            dlog_proofs_i_list: Pairs::new(),
            s_i: Scalar::ZERO,
            rec_seed_list: Pairs::new(),
            seed_ot_receivers: Pairs::new(),
            seed_i_j_list: Pairs::new(),
            seed_ot_senders: Pairs::new(),
        }
    }

    ///
    pub fn key_rotation<R: RngCore + CryptoRng>(
        oldshare: &Keyshare,
        rng: &mut R,
    ) -> Self {
        let party = Party {
            ranks: oldshare.rank_list.clone(),
            party_id: oldshare.party_id,
            t: oldshare.threshold,
        };
        Self::new(
            party,
            rng,
            Some(&oldshare.x_i_list[oldshare.party_id as usize]),
        )
    }

    /// Initialize DKG state for import an exteral key share.
    pub fn from_external_share<R: RngCore + CryptoRng>(
        n: usize,
        t: usize,
        party_id: usize,
        x_i: &NonZeroScalar,
        rng: &mut R,
    ) -> Self {
        Self::new(Party::new(n, t, party_id), rng, Some(x_i))
    }

    ///
    pub fn generate_msg1(&self) -> KeygenMsg1 {
        KeygenMsg1 {
            from_id: self.party_id,
            session_id: *self.sid_i_list.find_pair(self.party_id),
            commitment: *self.commitment_list.find_pair(self.party_id),
            x_i: *self.x_i_list.find_pair(self.party_id),
        }
    }

    pub fn calculate_commitment_2(&self) -> [u8; 32] {
        let chain_code_sid = self.chain_code_sids.find_pair(self.party_id);
        hash_commitment_2(&self.final_session_id, chain_code_sid, &self.r_i_2)
    }

    /// Round 1.
    pub fn handle_msg1<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        msgs: Vec<KeygenMsg1>,
    ) -> Result<Vec<KeygenMsg2>, KeygenError> {
        if msgs.len() != self.ranks.len() - 1 {
            return Err(KeygenError::MissingMessage);
        }

        for msg in msgs {
            self.sid_i_list.push(msg.from_id, msg.session_id);
            self.x_i_list.push(msg.from_id, msg.x_i);
            self.commitment_list.push(msg.from_id, msg.commitment);
        }

        // Check that x_i_list contains unique elements
        if HashSet::<FieldBytes>::from_iter(
            self.x_i_list.iter().map(|(_, x)| x.to_bytes()),
        )
        .len()
            != self.x_i_list.len()
        {
            return Err(KeygenError::NotUniqueXiValues);
        }

        // TODO: Should parties be initialized with rank_list and x_i_list? Ask Vlad.
        self.final_session_id = self
            .sid_i_list
            .iter()
            .fold(Sha256::new(), |hash, (_, sid)| hash.chain_update(sid))
            .finalize()
            .into();

        let dlog_proofs = {
            // Setup transcript for DLog proofs.
            let mut dlog_transcript = Transcript::new_dlog_proof(
                &self.final_session_id,
                self.party_id as usize,
                &DLOG_PROOF1_LABEL,
                &DKG_LABEL,
            );

            self.polynomial
                .iter()
                .map(|f_i| {
                    DLogProof::prove(
                        f_i,
                        &ProjectivePoint::GENERATOR,
                        &mut dlog_transcript,
                        rng,
                    )
                })
                .collect::<Vec<_>>()
        };

        let mut output = vec![];

        self.base_ot_receivers = other_parties(&self.ranks, self.party_id)
            .map(|p| {
                let base_ot_session_id = get_base_ot_session_id(
                    self.party_id as usize,
                    p as usize,
                    &self.final_session_id,
                );

                let mut msg1 = ZS::<EndemicOTMsg1>::default();
                let receiver = EndemicOTReceiver::new(
                    &base_ot_session_id,
                    &mut msg1,
                    rng,
                );

                output.push(KeygenMsg2 {
                    from_id: self.party_id,
                    to_id: p,
                    ot: msg1,

                    r_i: *self.r_i_list.find_pair(self.party_id),
                    dlog_proofs: dlog_proofs.clone(),
                    big_f_i_vec: self
                        .big_f_i_vecs
                        .find_pair(self.party_id)
                        .clone(),
                });

                Ok((p, receiver))
            })
            .collect::<Result<Vec<_>, KeygenError>>()?
            .into();

        Ok(output)
    }

    /// Round 2.
    pub fn handle_msg2<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        msgs: Vec<KeygenMsg2>,
    ) -> Result<Vec<KeygenMsg3>, KeygenError> {
        // FIXME: proper validation
        if msgs.len() != self.ranks.len() - 1 {
            return Err(KeygenError::MissingMessage);
        }

        for msg in &msgs {
            if msg.big_f_i_vec.coeffs.len() != self.t as usize {
                return Err(KeygenError::InvalidMessage);
            }
            if msg.dlog_proofs.len() != self.t as usize {
                return Err(KeygenError::InvalidMessage);
            }

            self.r_i_list.push(msg.from_id, msg.r_i);
            self.big_f_i_vecs.push(msg.from_id, msg.big_f_i_vec.clone());
            self.dlog_proofs_i_list
                .push(msg.from_id, msg.dlog_proofs.clone());
        }

        for party_id in 0..self.ranks.len() as u8 {
            if party_id == self.party_id {
                continue;
            }

            let x_i = self.x_i_list.find_pair(party_id);
            let r_i = self.r_i_list.find_pair(party_id);
            let sid = self.sid_i_list.find_pair(party_id);
            let commitment = self.commitment_list.find_pair(party_id);
            let big_f_i_vector = self.big_f_i_vecs.find_pair(party_id);

            let commit_hash = hash_commitment(
                sid,
                party_id as usize,
                self.ranks[party_id as usize] as usize,
                x_i,
                big_f_i_vector,
                r_i,
            );

            if commit_hash.ct_ne(commitment).into() {
                return Err(KeygenError::InvalidCommitmentHash);
            }

            {
                let mut points = big_f_i_vector.points();
                if self.key_refresh {
                    // for key refresh first point should be IDENTITY
                    if points.next() != Some(&ProjectivePoint::IDENTITY) {
                        return Err(KeygenError::InvalidPolynomialPoint);
                    }
                }
                if points.any(|p| p.is_identity().into()) {
                    return Err(KeygenError::InvalidPolynomialPoint);
                }
            }

            verify_dlog_proofs(
                &self.final_session_id,
                party_id as usize,
                self.dlog_proofs_i_list.find_pair(party_id),
                big_f_i_vector.points(),
            )?;
        }

        // 6.d
        for (_, v) in self.big_f_i_vecs.iter() {
            self.big_f_vec.add_mut(v); // big_f_vec += v; big_vec +
        }

        let public_key = self.big_f_vec.get_constant();

        if self.key_refresh {
            // check that public_key == IDENTITY
            if public_key != ProjectivePoint::IDENTITY {
                return Err(KeygenError::InvalidPolynomialPoint);
            }
        }

        Ok(msgs
            .into_iter()
            .map(|msg| {
                assert_eq!(msg.to_id, self.party_id);

                let rank = self.ranks[msg.from_id as usize];

                let sid = get_base_ot_session_id(
                    msg.from_id as usize,
                    self.party_id as usize,
                    &self.final_session_id,
                );
                let mut base_ot_msg2 = ZS::<EndemicOTMsg2>::default();

                let sender_output = EndemicOTSender::process(
                    &sid,
                    &msg.ot,
                    &mut base_ot_msg2,
                    rng,
                );

                let mut all_but_one_sender_seed =
                    ZS::<SenderOTSeed>::default();
                let mut pprf_output = ZS::<PPRFOutput>::default();

                let all_but_one_session_id = get_all_but_one_session_id(
                    self.party_id as usize,
                    msg.from_id as usize,
                    &self.final_session_id,
                );

                build_pprf(
                    &all_but_one_session_id,
                    &sender_output,
                    &mut all_but_one_sender_seed,
                    &mut pprf_output,
                );

                self.seed_ot_senders
                    .push(msg.from_id, all_but_one_sender_seed);

                let seed_i_j = if msg.from_id > self.party_id {
                    let seed_i_j = rng.gen();
                    self.seed_i_j_list.push(msg.from_id, seed_i_j);
                    Some(seed_i_j)
                } else {
                    None
                };

                let x_i = &self.x_i_list.find_pair(msg.from_id);
                let d_i = self.polynomial.derivative_at(rank as usize, x_i);

                KeygenMsg3 {
                    from_id: self.party_id,
                    to_id: msg.from_id,

                    base_ot_msg2,
                    pprf_output,
                    seed_i_j,
                    d_i,
                    big_f_vec: self.big_f_vec.clone(),
                    chain_code_sid: *self
                        .chain_code_sids
                        .find_pair(self.party_id),
                    r_i_2: self.r_i_2,
                }
            })
            .collect::<Vec<_>>())
    }

    /// Round 3.
    pub fn handle_msg3<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        msgs: Vec<KeygenMsg3>,
        commitment_2_list: &[[u8; 32]],
    ) -> Result<KeygenMsg4, KeygenError> {
        if msgs.len() != self.ranks.len() - 1 {
            return Err(KeygenError::MissingMessage);
        }

        for msg3 in msgs {
            if msg3.big_f_vec != self.big_f_vec {
                return Err(KeygenError::BigFVecMismatch);
            }

            self.d_i_list.push(msg3.from_id, msg3.d_i);

            let receiver = self.base_ot_receivers.pop_pair(msg3.from_id);
            let receiver_output = receiver.process(&msg3.base_ot_msg2);

            let mut all_but_one_receiver_seed =
                ZS::<ReceiverOTSeed>::default();

            let all_but_one_session_id = get_all_but_one_session_id(
                msg3.from_id as usize,
                self.party_id as usize,
                &self.final_session_id,
            );

            eval_pprf(
                &all_but_one_session_id,
                &receiver_output,
                &msg3.pprf_output,
                &mut all_but_one_receiver_seed,
            )
            .map_err(KeygenError::PPRFError)?;

            self.seed_ot_receivers
                .push(msg3.from_id, all_but_one_receiver_seed);
            if let Some(seed_j_i) = msg3.seed_i_j {
                self.rec_seed_list.push(msg3.from_id, seed_j_i);
            }

            // Verify commitments
            let commitment_2 = commitment_2_list
                .get(msg3.from_id as usize)
                .ok_or(KeygenError::InvalidMessage)?;

            let commit_hash = hash_commitment_2(
                &self.final_session_id,
                &msg3.chain_code_sid,
                &msg3.r_i_2,
            );

            if commit_hash.ct_ne(commitment_2).into() {
                return Err(KeygenError::InvalidCommitmentHash);
            }

            self.chain_code_sids.push(msg3.from_id, msg3.chain_code_sid);
        }

        // Generate common root_chain_code from chain_code_sids
        self.root_chain_code = self
            .chain_code_sids
            .iter()
            .fold(Sha256::new(), |hash, (_, sid)| hash.chain_update(sid))
            .finalize()
            .into();

        for ((_, big_f_i_vec), (_, f_i_val)) in
            self.big_f_i_vecs.iter().zip(self.d_i_list.iter())
        {
            let coeffs = big_f_i_vec.derivative_coeffs(
                self.ranks[self.party_id as usize] as usize,
            );
            let valid = feldman_verify(
                coeffs,
                self.x_i_list.find_pair(self.party_id),
                f_i_val,
                &ProjectivePoint::GENERATOR,
            );

            if !valid {
                return Err(KeygenError::FailedFelmanVerify);
            }
        }

        self.s_i = self.d_i_list.iter().map(|(_, s)| s).sum();
        let big_s_i = ProjectivePoint::GENERATOR * self.s_i;

        // Use the root_chain_code in the final dlog proof
        // so that all parties are sure they generated the same root_chain_code
        let final_session_id_with_root_chain_code = {
            let mut buf = [0u8; 32];
            let mut transcript = Transcript::new(&DKG_LABEL);
            transcript
                .append_message(b"final_session_id", &self.final_session_id);
            transcript
                .append_message(b"root_chain_code", &self.root_chain_code);
            transcript
                .challenge_bytes(&DLOG_SESSION_ID_WITH_CHAIN_CODE, &mut buf);
            buf
        };
        let proof = {
            let mut transcript = Transcript::new_dlog_proof(
                &final_session_id_with_root_chain_code,
                self.party_id as usize,
                &DLOG_PROOF2_LABEL,
                &DKG_LABEL,
            );

            DLogProof::prove(
                &self.s_i,
                &ProjectivePoint::GENERATOR,
                &mut transcript,
                rng,
            )
        };

        Ok(KeygenMsg4 {
            from_id: self.party_id,
            proof,
            big_s_i: big_s_i.to_affine(),
            public_key: self.big_f_vec.get_constant().to_affine(),
        })
    }

    /// Round 4.
    pub fn handle_msg4(
        &mut self,
        msgs: Vec<KeygenMsg4>,
    ) -> Result<Keyshare, KeygenError> {
        if msgs.len() != self.ranks.len() - 1 {
            return Err(KeygenError::MissingMessage);
        }

        let public_key = self.big_f_vec.get_constant().to_affine();
        let mut big_s_list = Pairs::new();
        let mut proof_list = Pairs::new();

        for msg in msgs {
            if msg.public_key != public_key {
                return Err(KeygenError::PublicKeyMismatch);
            }

            big_s_list.push(msg.from_id, msg.big_s_i.to_curve());
            proof_list.push(msg.from_id, msg.proof);
        }

        let final_session_id_with_root_chain_code = {
            let mut buf = [0u8; 32];
            let mut transcript = Transcript::new(&DKG_LABEL);
            transcript
                .append_message(b"final_session_id", &self.final_session_id);
            transcript
                .append_message(b"root_chain_code", &self.root_chain_code);
            transcript
                .challenge_bytes(&DLOG_SESSION_ID_WITH_CHAIN_CODE, &mut buf);
            buf
        };

        for ((party_id, big_s_i), (_, dlog_proof)) in
            big_s_list.iter().zip(proof_list.iter())
        {
            let mut transcript = Transcript::new_dlog_proof(
                &final_session_id_with_root_chain_code,
                *party_id as usize,
                &DLOG_PROOF2_LABEL,
                &DKG_LABEL,
            );
            if dlog_proof
                .verify(big_s_i, &ProjectivePoint::GENERATOR, &mut transcript)
                .unwrap_u8()
                == 0
            {
                return Err(KeygenError::InvalidDLogProof);
            }
        }

        for (party_id, x_i) in self.x_i_list.iter() {
            if party_id == &self.party_id {
                continue;
            }

            let party_rank = self.ranks[*party_id as usize];

            let coeff_multipliers = polynomial_coeff_multipliers(
                x_i,
                party_rank as usize,
                self.ranks.len(),
            );

            let expected_point: ProjectivePoint = self
                .big_f_vec
                .points()
                .zip(coeff_multipliers)
                .map(|(point, coeff)| point * &coeff)
                .sum();

            if expected_point != *big_s_list.find_pair(*party_id) {
                return Err(KeygenError::BigSMismatch);
            }
        }

        big_s_list.push(self.party_id, ProjectivePoint::GENERATOR * self.s_i);

        check_secret_recovery(
            &self.x_i_list.remove_ids(),
            &self.ranks,
            &big_s_list.remove_ids(),
            &public_key.to_curve(),
        )?;

        let share = Keyshare {
            total_parties: self.ranks.len() as u8,
            threshold: self.t,
            party_id: self.party_id,
            rank_list: self.ranks.clone(),
            public_key,
            root_chain_code: self.root_chain_code,
            x_i_list: self.x_i_list.remove_ids(),
            big_s_list: big_s_list
                .remove_ids()
                .iter()
                .map(|p| p.to_affine())
                .collect(),
            s_i: self.s_i,
            sent_seed_list: self.seed_i_j_list.remove_ids(),
            seed_ot_receivers: self.seed_ot_receivers.remove_ids(),
            seed_ot_senders: self.seed_ot_senders.remove_ids(),
            rec_seed_list: self.rec_seed_list.remove_ids(),
            final_session_id: self.final_session_id,
        };

        Ok(share)
    }
}

///
pub struct RefreshShare {
    /// Rank of each party. Initialize by vector of zeroes if your
    /// external key share does not have them.
    pub rank_list: Vec<u8>,
    /// Threshold value
    pub threshold: u8,
    /// Party Id of the sender
    pub party_id: u8,
    /// Public key.
    pub public_key: AffinePoint,
    /// Root chain code (used to derive child public keys)
    pub root_chain_code: [u8; 32],
    /// Private key additive share
    pub s_i: Scalar,
    /// List of s_i * G for each party. That is big_s_list[party_id] == s_i *G.
    pub big_s_list: Vec<AffinePoint>,
    ///
    pub x_i_list: Vec<NonZeroScalar>,
}

impl From<Keyshare> for RefreshShare {
    fn from(share: Keyshare) -> Self {
        Self {
            rank_list: share.rank_list.clone(),
            party_id: share.party_id,
            threshold: share.threshold,
            root_chain_code: share.root_chain_code,
            public_key: share.public_key,
            s_i: share.s_i,
            big_s_list: share.big_s_list.clone(),
            x_i_list: share.x_i_list.clone(),
        }
    }
}

impl Keyshare {
    /// Finish key refresh protocol. This method might be used for
    /// import of a key share generated by another protocol. Type R is
    /// anything that could be converted to RefreshShare.
    pub fn finish_key_rotation<R: Into<RefreshShare>>(
        &mut self,
        old_keyshare: R,
    ) -> Result<(), KeygenError> {
        let old_keyshare: RefreshShare = old_keyshare.into();

        // checks for new_keyshare
        let cond1 = (self.rank_list == old_keyshare.rank_list)
            && (self.party_id == old_keyshare.party_id)
            && (self.threshold == old_keyshare.threshold)
            && (self.big_s_list.len() == old_keyshare.big_s_list.len())
            && (self.x_i_list.len() == old_keyshare.x_i_list.len());

        cond1.then_some(()).ok_or(KeygenError::InvalidKeyRefresh)?;

        let mut cond2 = true;
        for (l, r) in self.x_i_list.iter().zip(&old_keyshare.x_i_list) {
            if l as &Scalar != r as &Scalar {
                cond2 = false;
            }
        }
        cond2.then_some(()).ok_or(KeygenError::InvalidKeyRefresh)?;

        // update existed keyshare with ephemeral keyshare
        self.public_key = old_keyshare.public_key;
        self.root_chain_code = old_keyshare.root_chain_code;
        self.s_i += old_keyshare.s_i;

        let new_big_s_list = old_keyshare
            .big_s_list
            .iter()
            .zip(&self.big_s_list)
            .map(|(p1, p2)| p1.to_curve() + p2.to_curve())
            .collect::<Vec<_>>();

        // check secret recovery
        check_secret_recovery(
            &self.x_i_list,
            &self.rank_list,
            &new_big_s_list,
            &self.public_key.to_curve(),
        )?;

        self.big_s_list =
            new_big_s_list.into_iter().map(|p| p.to_affine()).collect();

        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use serde::de::DeserializeOwned;

    use super::*;

    fn check_bincode<T: Serialize + DeserializeOwned>(v: &T) {
        let bytes =
            bincode::serde::encode_to_vec(v, bincode::config::standard())
                .unwrap();
        let _: (T, _) = bincode::serde::decode_from_slice(
            &bytes,
            bincode::config::standard(),
        )
        .unwrap();
    }

    fn check_json<T: Serialize + DeserializeOwned>(v: &T) {
        let bytes = serde_json::to_string(v).unwrap();
        let _: T = serde_json::from_str(&bytes).unwrap();
    }

    fn check_cbor<T: Serialize + DeserializeOwned>(v: &T) {
        let mut w = vec![];
        ciborium::into_writer(v, &mut w).unwrap();

        let _: T = ciborium::from_reader(w.as_ref() as &[u8]).unwrap();
    }

    pub fn check_serde<T: Serialize + DeserializeOwned>(messages: &[T]) {
        for msg in messages {
            check_bincode(msg);
            check_json(msg);
            check_cbor(msg);
        }
    }

    fn init_states(n: u8, t: u8) -> Vec<State> {
        let mut rng = rand::thread_rng();

        (0..n)
            .map(|party_id| {
                State::new(
                    Party {
                        ranks: vec![0u8; n as usize],
                        party_id,
                        t,
                    },
                    &mut rng, // different seed for each party
                    None,
                )
            })
            .collect()
    }

    pub fn dkg(n: u8, t: u8) -> Vec<Keyshare> {
        let parties = init_states(n, t);

        dkg_inner(parties)
    }

    pub fn dkg_inner(mut parties: Vec<State>) -> Vec<Keyshare> {
        let mut rng = rand::thread_rng();

        let msg1: Vec<KeygenMsg1> =
            parties.iter_mut().map(|p| p.generate_msg1()).collect();

        check_serde(&msg1);

        let mut msg2: Vec<KeygenMsg2> = vec![];

        for party in &mut parties {
            let batch: Vec<KeygenMsg1> = msg1
                .iter()
                .filter(|msg| msg.from_id != party.party_id)
                .cloned()
                .collect();
            msg2.extend(party.handle_msg1(&mut rng, batch).unwrap());
        }

        check_serde(&msg2);

        let mut msg3: Vec<KeygenMsg3> = vec![];

        for party in &mut parties {
            let batch: Vec<KeygenMsg2> = msg2
                .iter()
                .filter(|msg| msg.to_id == party.party_id)
                .cloned()
                .collect();

            msg3.extend(party.handle_msg2(&mut rng, batch).unwrap());
        }

        check_serde(&msg3);

        let mut msg4: Vec<KeygenMsg4> = vec![];

        let commitment_2_list = parties
            .iter()
            .map(|p| p.calculate_commitment_2())
            .collect::<Vec<_>>();

        for party in &mut parties {
            let batch: Vec<KeygenMsg3> = msg3
                .iter()
                .filter(|msg| msg.to_id == party.party_id)
                .cloned()
                .collect();

            msg4.push(
                party
                    .handle_msg3(&mut rng, batch, &commitment_2_list)
                    .unwrap(),
            );
        }

        check_serde(&msg4);

        parties
            .into_iter()
            .map(|mut party| {
                let batch: Vec<KeygenMsg4> = msg4
                    .iter()
                    .filter(|msg| msg.from_id != party.party_id)
                    .cloned()
                    .collect();

                party.handle_msg4(batch).unwrap()
            })
            .collect()
    }

    #[test]
    fn dkg2_out_of_2() {
        dkg(2, 2);
    }

    #[test]
    fn dkg2_out_of_3() {
        dkg(3, 2);
    }

    #[test]
    fn key_rotation() {
        let mut rng = rand::thread_rng();

        let shares = dkg(3, 2);

        let rotation_states = shares
            .iter()
            .map(|s| State::key_rotation(s, &mut rng))
            .collect::<Vec<_>>();

        let mut new_shares = dkg_inner(rotation_states);

        new_shares.iter_mut().zip(shares).for_each(
            |(new_share, old_share)| {
                new_share.finish_key_rotation(old_share).unwrap()
            },
        );
    }
}
