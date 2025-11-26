// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! The structs and functions for implementing DKLS23 signing operations
//! Presignatures should be used only for one message signature
use derivation_path::DerivationPath;
use k256::{
    ecdsa::Signature,
    elliptic_curve::{
        group::prime::PrimeCurveAffine, ops::Reduce,
        point::AffineCoordinates, subtle::ConstantTimeEq,
    },
    AffinePoint, ProjectivePoint, Scalar, U256,
};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use sl_mpc_mate::bip32::BIP32Error;

use crate::dsg::{
    combine_partial_signature, derive_with_offset, get_lagrange_coeff,
    get_zeta_i, PartialSignature, PreSignature, SignMsg4, PS,
};
pub use crate::error::SignError;
pub use crate::error::SignOTVariantError;
use crate::{constants::*, dkg::Keyshare, pairs::*, utils::*};
use sl_oblivious::endemic_ot::EndemicOTReceiver;
use sl_oblivious::rvole_ot_variant::{RVOLEMsg1, RVOLEMsg2};
use sl_oblivious::rvole_ot_variant::{RVOLEReceiver, RVOLESender};

/// Type for the sign gen message 1.
#[derive(Clone, Serialize, Deserialize)]
pub struct SignMsg1 {
    pub from_id: u8,
    pub session_id: [u8; 32],
    pub commitment_r_i: [u8; 32],
    // Make SignMsg1 and dsg::SignMsg1 incompatible.
    // This allows a party to tell from the first message it receives
    // which protocol variant its counter-party is expecting to use.
    pub compatibility_breaking_field: u8,
}

/// Type for the sign gen message 2. P2P
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SignMsg2 {
    pub from_id: u8,
    pub to_id: u8,

    /// final_session_id
    pub final_session_id: [u8; 32],

    pub mta_msg_1: ZS<RVOLEMsg1>,
}

/// Type for the sign gen message 3. P2P
#[allow(missing_docs)]
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SignMsg3 {
    pub from_id: u8,
    pub to_id: u8,

    /// final_session_id
    pub final_session_id: [u8; 32],

    pub mta_msg2: ZS<RVOLEMsg2>,
    pub digest_i: [u8; 32],
    pub pk_i: AffinePoint,
    pub big_r_i: AffinePoint,
    pub blind_factor: [u8; 32],
    pub gamma_v: AffinePoint,
    pub gamma_u: AffinePoint,
    pub psi: Scalar,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct State {
    pub keyshare: Keyshare,
    pub sid_list: Pairs<[u8; 32]>,
    pub phi_i: Scalar,
    pub r_i: Scalar,
    pub sk_i: Scalar,
    pub big_r_i: AffinePoint,
    pub pk_i: AffinePoint,
    pub blind_factor: [u8; 32],
    pub commitment_r_i_list: Pairs<[u8; 32]>,
    pub final_session_id: [u8; 32],
    pub digest_i: [u8; 32],
    #[zeroize(skip)]
    #[allow(clippy::type_complexity)]
    pub mta_receiver_list: Pairs<(
        ZS<RVOLEReceiver>,
        Box<EndemicOTReceiver>,
        Box<EndemicOTReceiver>,
        Scalar,
    )>,
    pub additive_offset: Scalar,
    pub derived_public_key: AffinePoint,
    pub sender_additive_shares: Vec<[Scalar; 2]>,
}

fn other_parties<T>(
    a_list: &Pairs<T>,
    party_id: u8,
) -> impl Iterator<Item = u8> + '_ {
    a_list
        .iter()
        .map(|(p, _)| *p)
        .filter(move |p| *p != party_id)
}

impl State {
    pub fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        keyshare: Keyshare,
        chain_path: &DerivationPath,
    ) -> Result<Self, BIP32Error> {
        let party_id = keyshare.party_id;

        let session_id: [u8; 32] = rng.gen();
        let phi_i = Scalar::generate_biased(rng);
        let r_i = Scalar::generate_biased(rng);
        let blind_factor = rng.gen();

        let big_r_i = ProjectivePoint::GENERATOR * r_i;
        let commitment_r_i =
            hash_commitment_r_i(&session_id, &big_r_i, &blind_factor);

        let (additive_offset, derived_public_key) = derive_with_offset(
            &keyshare.public_key.to_curve(),
            &keyshare.root_chain_code,
            chain_path,
        )?;

        // can not fail because T != 0
        let threshold_inv =
            Scalar::from(keyshare.threshold as u32).invert().unwrap();
        let additive_offset = additive_offset * threshold_inv;

        Ok(Self {
            sender_additive_shares: Vec::with_capacity(
                keyshare.threshold as usize - 1,
            ),
            keyshare,
            sid_list: Pairs::new_with_item(party_id, session_id),
            phi_i,
            r_i,
            sk_i: Scalar::ZERO,
            big_r_i: big_r_i.to_affine(),
            pk_i: AffinePoint::IDENTITY,
            blind_factor,
            additive_offset,
            derived_public_key: derived_public_key.to_affine(),
            commitment_r_i_list: Pairs::new_with_item(
                party_id,
                commitment_r_i,
            ),
            final_session_id: [0u8; 32],
            digest_i: [0; 32],
            mta_receiver_list: Pairs::new(),
        })
    }

    //Round 1
    pub fn generate_msg1(&mut self) -> SignMsg1 {
        let party_id = self.keyshare.party_id;

        SignMsg1 {
            from_id: party_id,
            session_id: *self.sid_list.find_pair(party_id),
            commitment_r_i: *self.commitment_r_i_list.find_pair(party_id),
            compatibility_breaking_field: 0, // A dummy value.
        }
    }

    /// Round 1
    pub fn handle_msg1<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        msgs: Vec<SignMsg1>,
    ) -> Result<Vec<SignMsg2>, SignOTVariantError> {
        if msgs.len() != self.keyshare.threshold as usize - 1 {
            return Err(SignOTVariantError::MissingMessage);
        }

        for msg in msgs {
            // make sure msg is unique
            if self
                .sid_list
                .iter()
                .any(|(p, v)| (p != &msg.from_id) && (v == &msg.session_id))
                || self
                    .commitment_r_i_list
                    .iter()
                    .any(|(_, v)| v == &msg.commitment_r_i)
            {
                return Err(SignOTVariantError::MissingMessage);
            }

            self.sid_list.push(msg.from_id, msg.session_id);
            self.commitment_r_i_list
                .push(msg.from_id, msg.commitment_r_i);
        }

        self.final_session_id = self
            .sid_list
            .iter()
            .fold(Sha256::new(), |hash, (_, sid)| hash.chain_update(sid))
            .chain_update(self.keyshare.final_session_id)
            .finalize()
            .into();

        self.digest_i = {
            let mut h = Sha256::new();
            h.update(DSG_LABEL);
            for (key, commitment_i) in self.commitment_r_i_list.iter() {
                h.update((*key as u32).to_be_bytes());
                h.update(self.sid_list.find_pair(*key));
                h.update(commitment_i);
            }
            h.update(DIGEST_I_LABEL);
            h.finalize().into()
        };

        let party_id = self.keyshare.party_id;

        Ok(other_parties(&self.sid_list, party_id)
            .map(|sender_id| {
                let sid = mta_session_id(
                    &self.final_session_id,
                    sender_id,
                    party_id,
                );

                let mut mta_msg_1 = ZS::<RVOLEMsg1>::default();
                let (mta_receiver, ot_receiver_a, ot_receiver_b, chi_i_j) =
                    RVOLEReceiver::new(sid, &mut mta_msg_1, rng);

                self.mta_receiver_list.push(
                    sender_id,
                    (
                        mta_receiver.into(),
                        ot_receiver_a,
                        ot_receiver_b,
                        chi_i_j,
                    ),
                );

                SignMsg2 {
                    from_id: party_id,
                    to_id: sender_id,
                    final_session_id: self.final_session_id,

                    mta_msg_1,
                }
            })
            .collect())
    }

    /// Round 2
    /// Handle first P2P message from each party.
    pub fn handle_msg2<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        msgs: Vec<SignMsg2>,
    ) -> Result<Vec<SignMsg3>, SignOTVariantError> {
        if msgs.len() != self.keyshare.threshold as usize - 1 {
            return Err(SignOTVariantError::MissingMessage);
        }

        let my_party_id = self.keyshare.party_id;

        let zeta_i = get_zeta_i(
            &self.keyshare,
            &self.digest_i,
            other_parties(&self.sid_list, my_party_id),
        );

        let coeff = if self.keyshare.rank_list.iter().all(|&r| r == 0) {
            get_lagrange_coeff(
                &self.keyshare,
                other_parties(&self.sid_list, my_party_id),
            )
        } else {
            // let betta_coeffs = get_birkhoff_coefficients(&self.keyshare, &party_idx_to_id_map);
            // *betta_coeffs
            //     .get(&(my_party_id as usize))
            //     .expect("betta_i not found") // FIXME

            unimplemented!()
        };

        self.sk_i = coeff * self.keyshare.s_i + self.additive_offset + zeta_i;
        self.pk_i = (ProjectivePoint::GENERATOR * self.sk_i).to_affine();

        let output: Vec<SignMsg3> = msgs
            .into_iter()
            .map(|msg| {
                if msg.final_session_id.ct_ne(&self.final_session_id).into() {
                    return Err(SignOTVariantError::InvalidFinalSessionID);
                }

                let party_id = msg.from_id;

                let sid = mta_session_id(
                    &self.final_session_id,
                    my_party_id,
                    party_id,
                );

                let mut mta_msg2 = ZS::<RVOLEMsg2>::default();

                let [c_u, c_v] = RVOLESender::process(
                    &sid,
                    &[self.r_i, self.sk_i],
                    &msg.mta_msg_1,
                    &mut mta_msg2,
                    rng,
                )
                .map_err(|_| SignOTVariantError::Rvole)?;

                let gamma_u = ProjectivePoint::GENERATOR * c_u;
                let gamma_v = ProjectivePoint::GENERATOR * c_v;
                let (_mta_receiver, _ot_receiver_a, _ot_receiver_b, chi_i_j) =
                    self.mta_receiver_list.find_pair(party_id);
                let psi = self.phi_i - chi_i_j;

                self.sender_additive_shares.push([c_u, c_v]);

                Ok(SignMsg3 {
                    from_id: self.keyshare.party_id,
                    to_id: party_id,

                    final_session_id: self.final_session_id,
                    mta_msg2,
                    digest_i: self.digest_i,
                    pk_i: self.pk_i,
                    big_r_i: self.big_r_i,
                    blind_factor: self.blind_factor,
                    gamma_v: gamma_v.to_affine(),
                    gamma_u: gamma_u.to_affine(),
                    psi,
                })
            })
            .collect::<Result<Vec<_>, SignOTVariantError>>()?;

        Ok(output)
    }

    /// Round 3 returns the presigs
    /// Handle second P2P message from each party.
    /// FIXME: add comment about using
    pub fn handle_msg3(
        &mut self,
        msgs: Vec<SignMsg3>,
    ) -> Result<PreSignature, SignOTVariantError> {
        if msgs.len() != self.keyshare.threshold as usize - 1 {
            return Err(SignOTVariantError::MissingMessage);
        }

        let mut big_r_star = ProjectivePoint::IDENTITY;
        let mut sum_pk_j = ProjectivePoint::IDENTITY;
        let mut sum_psi_j_i = Scalar::ZERO;

        let mut receiver_additive_shares = vec![];

        for msg3 in msgs {
            if msg3.final_session_id.ct_ne(&self.final_session_id).into() {
                return Err(SignOTVariantError::InvalidFinalSessionID);
            }

            let party_id = msg3.from_id;
            let (mta_receiver, ot_receiver_a, ot_receiver_b, chi_i_j) =
                self.mta_receiver_list.pop_pair(party_id);

            let [d_u, d_v] = mta_receiver
                .process(&msg3.mta_msg2, ot_receiver_a, ot_receiver_b)
                .map_err(|_| SignOTVariantError::Rvole)?;

            receiver_additive_shares.push([d_u, d_v]);

            let commitment = self.commitment_r_i_list.find_pair(party_id);
            let sid_i = self.sid_list.find_pair(party_id);

            if !verify_commitment_r_i(
                sid_i,
                &msg3.big_r_i.to_curve(),
                &msg3.blind_factor,
                commitment,
            ) {
                return Err(SignOTVariantError::InvalidCommitment);
            }

            if self.digest_i.ct_ne(&msg3.digest_i).into() {
                return Err(SignOTVariantError::InvalidDigest);
            }

            let big_r_j = msg3.big_r_i.to_curve();
            let pk_j = msg3.pk_i.to_curve();

            big_r_star += big_r_j;
            sum_pk_j += pk_j;
            sum_psi_j_i += &msg3.psi;

            let cond1 = (big_r_j * chi_i_j)
                == (ProjectivePoint::GENERATOR * d_u + msg3.gamma_u);
            if !cond1 {
                return Err(SignOTVariantError::Rvole);
            }

            let cond2 = (pk_j * chi_i_j)
                == (ProjectivePoint::GENERATOR * d_v + msg3.gamma_v);
            if !cond2 {
                return Err(SignOTVariantError::Rvole);
            }
        }

        // new var
        let big_r = big_r_star + self.big_r_i;

        sum_pk_j += self.pk_i;

        // Checks
        if sum_pk_j != self.derived_public_key {
            return Err(SignOTVariantError::FailedCheck(
                "Consistency check 3 failed",
            ));
        }

        let mut sum_v = Scalar::ZERO;
        let mut sum_u = Scalar::ZERO;

        #[allow(clippy::needless_range_loop)]
        for i in 0..self.keyshare.threshold as usize - 1 {
            let sender_shares = &self.sender_additive_shares[i];
            let receiver_shares = &receiver_additive_shares[i];
            sum_u += sender_shares[0] + receiver_shares[0];
            sum_v += sender_shares[1] + receiver_shares[1];
        }

        let r_point = big_r.to_affine();
        let r_x: Scalar = Reduce::<U256>::reduce_bytes(&r_point.x());
        let phi_plus_sum_psi = self.phi_i + sum_psi_j_i;
        let s_0 = r_x * (self.sk_i * phi_plus_sum_psi + sum_v);
        let s_1 = self.r_i * phi_plus_sum_psi + sum_u;

        let pre_sign_result = PreSignature {
            from_id: self.keyshare.party_id,
            final_session_id: self.final_session_id,
            public_key: self.derived_public_key,
            phi_i: self.phi_i,
            r: r_point,
            s_0,
            s_1,
        };

        Ok(pre_sign_result)
    }
}

//Round 4: final round to compute the ECDSA signature from the presigs and the message
pub fn combine_signatures(
    partial: PartialSignature,
    msgs: Vec<SignMsg4>,
) -> Result<Signature, SignOTVariantError> {
    let t = msgs.len() + 1;

    let mut partial_signatures = Vec::with_capacity(t);

    partial_signatures.push(PS {
        final_session_id: partial.final_session_id,
        public_key: partial.public_key.to_curve(),
        message_hash: partial.message_hash,
        s_0: partial.s_0,
        s_1: partial.s_1,
        r: partial.r.to_curve(),
    });

    for msg in msgs {
        partial_signatures.push(PS {
            final_session_id: msg.session_id,
            s_0: msg.s_0,
            s_1: msg.s_1,

            public_key: partial.public_key.to_curve(),
            message_hash: partial.message_hash,
            r: partial.r.to_curve(),
        });
    }

    match combine_partial_signature(partial_signatures, t) {
        Ok(v) => Ok(v),
        Err(e) => Err(SignOTVariantError::from(e)),
    }
}

#[cfg(test)]
mod tests {
    use crate::dkg::{Party, RefreshShare};
    use std::str::FromStr;

    use super::*;

    use crate::dkg::tests::{check_serde, dkg, dkg_inner};
    use crate::dsg::create_partial_signature;

    fn dsg(shares: &[Keyshare]) {
        let mut rng = rand::thread_rng();

        let chain_path = DerivationPath::from_str("m").unwrap();
        let mut parties = shares
            .iter()
            .map(|s| State::new(&mut rng, s.clone(), &chain_path).unwrap())
            .collect::<Vec<_>>();

        let msg1: Vec<SignMsg1> =
            parties.iter_mut().map(|p| p.generate_msg1()).collect();

        check_serde(&msg1);

        let msg2 = parties.iter_mut().fold(vec![], |mut msg2, party| {
            let batch: Vec<SignMsg1> = msg1
                .iter()
                .filter(|msg| msg.from_id != party.keyshare.party_id)
                .cloned()
                .collect();
            msg2.extend(party.handle_msg1(&mut rng, batch).unwrap());
            msg2
        });

        check_serde(&msg2);

        let msg3 = parties.iter_mut().fold(vec![], |mut msg3, party| {
            let batch: Vec<SignMsg2> = msg2
                .iter()
                .filter(|msg| msg.to_id == party.keyshare.party_id)
                .cloned()
                .collect();
            msg3.extend(party.handle_msg2(&mut rng, batch).unwrap());
            msg3
        });

        check_serde(&msg3);

        let pre_signs = parties
            .iter_mut()
            .map(|party| {
                let batch: Vec<SignMsg3> = msg3
                    .iter()
                    .filter(|msg| msg.to_id == party.keyshare.party_id)
                    .cloned()
                    .collect();

                party.handle_msg3(batch).unwrap()
            })
            .collect::<Vec<_>>();

        check_serde(&pre_signs);

        let hash = [255; 32];

        let (partials, msg4): (Vec<_>, Vec<_>) = pre_signs
            .into_iter()
            .map(|pre| create_partial_signature(pre, hash))
            .unzip();
        // at this point the partial signatures are created you can store them for later usage
        // an example of a final signature is shown below.
        let _sigs = partials
            .into_iter()
            .map(|p| {
                let batch: Vec<SignMsg4> = msg4
                    .iter()
                    .filter(|msg| msg.from_id != p.party_id)
                    .cloned()
                    .collect();

                combine_signatures(p, batch)
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
    }

    #[test]
    fn sign_2_out_of_2() {
        let shares = dkg(2, 2);
        dsg(&shares[..2]);
    }

    #[test]
    fn sign_2_out_3() {
        let shares = dkg(3, 2);
        dsg(&shares[..2]);
    }

    #[test]
    fn sign_3_out_3() {
        let shares = dkg(3, 3);
        dsg(&shares[..3]);
    }

    #[test]
    fn sign_2_out_4() {
        let shares = dkg(4, 2);
        dsg(&shares[..2]);
    }

    #[test]
    fn sign_3_out_4() {
        let shares = dkg(4, 3);
        dsg(&shares[..3]);
    }

    #[test]
    fn sign_2_out_of_3_and_rotate_keyshares() {
        let mut rng = rand::thread_rng();

        let shares = dkg(3, 2);
        dsg(&shares[..2]);

        let rotation_states = shares
            .iter()
            .map(|s| crate::dkg::State::key_rotation(s, &mut rng).unwrap())
            .collect::<Vec<_>>();

        let new_shares = dkg_inner(rotation_states);

        // let's be creative and choose different set of shares
        dsg(&new_shares[1..]);
    }

    #[test]
    fn recover_lost_share_and_sign() {
        let mut rng = rand::thread_rng();

        let shares = dkg(3, 2);

        let public_key = shares[0].public_key;

        // party_0 key_share was lost
        let lost_keyshare_party_ids = vec![0];
        let party_with_lost_keyshare = Party {
            ranks: vec![0, 0, 0],
            t: 2,
            party_id: 0,
        };

        let refresh_shares = [
            RefreshShare::from_lost_keyshare(
                party_with_lost_keyshare,
                public_key,
                lost_keyshare_party_ids.clone(),
            ),
            RefreshShare::from_keyshare(
                &shares[1],
                Some(&lost_keyshare_party_ids),
            ),
            RefreshShare::from_keyshare(
                &shares[2],
                Some(&lost_keyshare_party_ids),
            ),
        ];

        let rotation_states = refresh_shares
            .iter()
            .map(|s| crate::dkg::State::key_refresh(s, &mut rng).unwrap())
            .collect::<Vec<_>>();

        let new_shares = dkg_inner(rotation_states);

        dsg(&new_shares[..2]);
    }
}
