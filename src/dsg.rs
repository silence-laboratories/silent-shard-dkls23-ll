//! The structs and functions for implementing DKLS23 signing operations
//! Presignatures should be used only for one message signature
use derivation_path::DerivationPath;
use k256::{
    ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey},
    elliptic_curve::{
        group::prime::PrimeCurveAffine, ops::Reduce,
        point::AffineCoordinates, subtle::ConstantTimeEq, PrimeField,
    },
    AffinePoint, ProjectivePoint, Scalar, U256,
};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use sl_mpc_mate::bip32::{derive_child_pubkey, BIP32Error};

use sl_oblivious::{
    rvole::{RVOLEOutput, RVOLEReceiver, RVOLESender},
    soft_spoken::Round1Output,
};

use crate::{dkg::Keyshare, pairs::*, utils::*};

pub use crate::error::SignError;

/// Type for the sign gen message 1.
#[derive(Clone, Serialize, Deserialize)]
pub struct SignMsg1 {
    pub from_id: u8,
    pub session_id: [u8; 32],
    pub commitment_r_i: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SignMsg2 {
    pub from_id: u8,
    pub to_id: u8,

    /// final_session_id
    pub final_session_id: [u8; 32],

    pub mta_msg_1: ZS<Round1Output>,
}

/// Type for the sign gen message 3. P2P
#[allow(missing_docs)]
#[derive(Clone, Serialize, Deserialize)]
pub struct SignMsg3 {
    pub from_id: u8,
    pub to_id: u8,

    pub mta_msg2: ZS<RVOLEOutput>,
    pub digest_i: [u8; 32],
    pub pk_i: AffinePoint,
    pub big_r_i: AffinePoint,
    pub blind_factor: [u8; 32],
    pub gamma_v: AffinePoint,
    pub gamma_u: AffinePoint,
    pub psi: Scalar,
}

/// Type for the sign gen message 4.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignMsg4 {
    pub from_id: u8,
    pub session_id: [u8; 32],
    pub s_0: Scalar,
    pub s_1: Scalar,
}

/// Result after pre-signature of party_i
#[derive(Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct PreSignature {
    pub from_id: u8,
    pub final_session_id: [u8; 32],
    pub public_key: AffinePoint,
    pub s_0: Scalar,
    pub s_1: Scalar,
    pub r: AffinePoint,
    pub phi_i: Scalar,
}

/// Partial signature of party_i
#[allow(missing_docs)]
#[derive(Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct PartialSignature {
    pub party_id: u8,

    pub final_session_id: [u8; 32],
    pub public_key: AffinePoint,
    pub message_hash: [u8; 32],
    pub s_0: Scalar,
    pub s_1: Scalar,
    pub r: AffinePoint,
}

#[derive(Serialize, Deserialize)]
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
    pub mta_receiver_list: Pairs<(ZS<RVOLEReceiver>, Scalar)>,
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
        }
    }

    /// Round 1
    pub fn handle_msg1<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        msgs: Vec<SignMsg1>,
    ) -> Result<Vec<SignMsg2>, SignError> {
        if msgs.len() != self.keyshare.threshold as usize - 1 {
            return Err(SignError::MissingMessage);
        }

        for msg in msgs {
            self.sid_list.push(msg.from_id, msg.session_id);
            self.commitment_r_i_list
                .push(msg.from_id, msg.commitment_r_i);
        }

        self.final_session_id = self
            .sid_list
            .iter()
            .fold(Sha256::new(), |hash, (_, sid)| hash.chain_update(sid))
            .finalize()
            .into();

        self.digest_i = {
            let mut h = Sha256::new();
            for (key, commitment_i) in self.commitment_r_i_list.iter() {
                h.update((*key as u32).to_be_bytes());
                h.update(self.sid_list.find_pair(*key));
                h.update(commitment_i);
            }

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

                let sender_ot_results = &self.keyshare.seed_ot_senders
                    [get_idx_from_id(self.keyshare.party_id, sender_id)
                        as usize];

                let mut mta_msg_1 = ZS::<Round1Output>::default();
                let (mta_receiver, chi_i_j) = RVOLEReceiver::new(
                    sid,
                    sender_ot_results,
                    &mut mta_msg_1,
                    rng,
                );

                self.mta_receiver_list
                    .push(sender_id, (mta_receiver.into(), chi_i_j));

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
    ) -> Result<Vec<SignMsg3>, SignError> {
        if msgs.len() != self.keyshare.threshold as usize - 1 {
            return Err(SignError::MissingMessage);
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
                    return Err(SignError::InvalidFinalSessionID);
                }

                let party_id = msg.from_id;

                let sid = mta_session_id(
                    &self.final_session_id,
                    my_party_id,
                    party_id,
                );

                let seed_ot_results = &self.keyshare.seed_ot_receivers
                    [get_idx_from_id(my_party_id, party_id) as usize];

                let mut mta_msg2 = ZS::<RVOLEOutput>::default();

                let [c_u, c_v] = RVOLESender::process(
                    &sid,
                    seed_ot_results,
                    &[self.r_i, self.sk_i],
                    &msg.mta_msg_1,
                    &mut mta_msg2,
                    rng,
                )
                .map_err(|_| SignError::AbortProtocolAndBanParty(party_id))?;

                let gamma_u = ProjectivePoint::GENERATOR * c_u;
                let gamma_v = ProjectivePoint::GENERATOR * c_v;
                let (_mta_receiver, chi_i_j) =
                    self.mta_receiver_list.find_pair(party_id);
                let psi = self.phi_i - chi_i_j;

                self.sender_additive_shares.push([c_u, c_v]);

                Ok(SignMsg3 {
                    from_id: self.keyshare.party_id,
                    to_id: party_id,

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
            .collect::<Result<Vec<_>, SignError>>()?;

        Ok(output)
    }

    /// Round 3 returns the presigs
    /// Handle second P2P message from each party.
    /// FIXME: add comment about using
    pub fn handle_msg3(
        &mut self,
        msgs: Vec<SignMsg3>,
    ) -> Result<PreSignature, SignError> {
        if msgs.len() != self.keyshare.threshold as usize - 1 {
            return Err(SignError::MissingMessage);
        }

        let mut big_r_star = ProjectivePoint::IDENTITY;
        let mut sum_pk_j = ProjectivePoint::IDENTITY;
        let mut sum_psi_j_i = Scalar::ZERO;

        let mut receiver_additive_shares = vec![];

        for msg3 in msgs {
            let party_id = msg3.from_id;
            let (mta_receiver, chi_i_j) =
                self.mta_receiver_list.pop_pair(party_id);

            let [d_u, d_v] = mta_receiver
                .process(&msg3.mta_msg2)
                .map_err(|_| SignError::AbortProtocolAndBanParty(party_id))?;

            receiver_additive_shares.push([d_u, d_v]);

            let commitment = self.commitment_r_i_list.find_pair(party_id);
            let sid_i = self.sid_list.find_pair(party_id);

            if !verify_commitment_r_i(
                sid_i,
                &msg3.big_r_i.to_curve(),
                &msg3.blind_factor,
                commitment,
            ) {
                return Err(SignError::InvalidCommitment);
            }

            if self.digest_i.ct_ne(&msg3.digest_i).into() {
                return Err(SignError::InvalidDigest);
            }

            let big_r_j = msg3.big_r_i.to_curve();
            let pk_j = msg3.pk_i.to_curve();

            big_r_star += big_r_j;
            sum_pk_j += pk_j;
            sum_psi_j_i += &msg3.psi;

            let cond1 = (big_r_j * chi_i_j)
                == (ProjectivePoint::GENERATOR * d_u + msg3.gamma_u);
            if !cond1 {
                return Err(SignError::AbortProtocolAndBanParty(party_id));
            }

            let cond2 = (pk_j * chi_i_j)
                == (ProjectivePoint::GENERATOR * d_v + msg3.gamma_v);
            if !cond2 {
                return Err(SignError::AbortProtocolAndBanParty(party_id));
            }
        }

        // new var
        let big_r = big_r_star + self.big_r_i;

        sum_pk_j += self.pk_i;

        // Checks
        if sum_pk_j != self.derived_public_key {
            return Err(SignError::FailedCheck("Consistency check 3 failed"));
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
        let r_x = Scalar::from_repr(r_point.x()).unwrap();
        //        let recid = r_point.y_is_odd().unwrap_u8();
        let phi_plus_sum_psi = self.phi_i + sum_psi_j_i;
        let s_0 = r_x * (self.sk_i * phi_plus_sum_psi + sum_v);
        let s_1 = self.r_i * phi_plus_sum_psi + sum_u;

        let pre_sign_result = PreSignature {
            from_id: self.keyshare.party_id,
            final_session_id: self.final_session_id,
            public_key: self.derived_public_key,
            phi_i: self.phi_i,
            r: big_r.to_affine(),
            s_0,
            s_1,
        };

        Ok(pre_sign_result)
    }
}

pub fn create_partial_signature(
    pre: PreSignature,
    hash: [u8; 32],
) -> (PartialSignature, SignMsg4) {
    let m = Scalar::reduce(U256::from_be_slice(&hash));
    let s_0 = m * pre.phi_i + pre.s_0;

    let partial = PartialSignature {
        party_id: pre.from_id,
        final_session_id: pre.final_session_id,
        public_key: pre.public_key,
        message_hash: hash,
        s_0,
        s_1: pre.s_1,
        r: pre.r,
    };

    let msg4 = SignMsg4 {
        from_id: pre.from_id,
        session_id: partial.final_session_id,
        s_0: partial.s_0,
        s_1: partial.s_1,
    };

    (partial, msg4)
}

/// Partial signature of party_i
#[derive(Zeroize, ZeroizeOnDrop)]
struct PS {
    /// final_session_id
    pub final_session_id: [u8; 32],

    /// public_key
    pub public_key: ProjectivePoint,

    /// 32 bytes message_hash
    pub message_hash: [u8; 32],

    /// s_0 Scalar
    pub s_0: Scalar,

    /// s_1 Scalar
    pub s_1: Scalar,

    /// R point
    pub r: ProjectivePoint,
}

//Round 4: final round to compute the ECDSA signature from the presigs and the message
pub fn combine_signatures(
    partial: PartialSignature,
    msgs: Vec<SignMsg4>,
) -> Result<Signature, SignError> {
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

    combine_partial_signature(partial_signatures, t)
}

// TODO: remove vectors
fn get_zeta_i(
    keyshare: &Keyshare,
    sig_id: &[u8; 32],
    partys: impl Iterator<Item = u8>,
) -> Scalar {
    let mut p_0_list = Vec::new();
    let mut p_1_list = Vec::new();

    for party_id in partys {
        if party_id < keyshare.party_id {
            p_0_list.push(party_id);
        }
        if party_id > keyshare.party_id {
            p_1_list.push(party_id);
        }
    }

    let mut sum_p_0 = Scalar::ZERO;
    for p_0_party in &p_0_list {
        let seed_j_i = keyshare.rec_seed_list[*p_0_party as usize];
        let mut hasher = Sha256::new();
        hasher.update(seed_j_i);
        hasher.update(sig_id);
        let value = Scalar::reduce(U256::from_be_slice(&hasher.finalize()));
        sum_p_0 += value;
    }

    let mut sum_p_1 = Scalar::ZERO;
    for p_1_party in &p_1_list {
        let seed_i_j = keyshare.sent_seed_list
            [*p_1_party as usize - keyshare.party_id as usize - 1];
        let mut hasher = Sha256::new();
        hasher.update(seed_i_j);
        hasher.update(sig_id);
        let value = Scalar::reduce(U256::from_be_slice(&hasher.finalize()));
        sum_p_1 += value;
    }

    sum_p_0 - sum_p_1
}

// fn get_birkhoff_coefficients(
//     keyshare: &Keyshare,
//     sign_party_ids: &[(usize, u8)],
// ) -> HashMap<usize, Scalar> {
//     let params = sign_party_ids
//         .iter()
//         .map(|(_, pid)| {
//             (
//                 *keyshare.x_i_list[*pid as usize],
//                 keyshare.rank_list[*pid as usize] as usize,
//             )
//         })
//         .collect::<Vec<_>>();

//     let betta_vec = birkhoff_coeffs::<Secp256k1>(&params);

//     sign_party_ids
//         .iter()
//         .zip(betta_vec.iter())
//         .map(|((_, pid), w_i)| (*pid as usize, *w_i))
//         .collect::<HashMap<_, _>>()
// }

fn get_lagrange_coeff(
    keyshare: &Keyshare,
    parties: impl Iterator<Item = u8>,
) -> Scalar {
    let mut coeff = Scalar::from(1u64);
    let pid = keyshare.party_id;
    let x_i = &keyshare.x_i_list[pid as usize] as &Scalar;

    for party_id in parties {
        let x_j = &*keyshare.x_i_list[party_id as usize]; //  as &Scalar;
        if x_i.ct_ne(x_j).into() {
            let sub = x_j - x_i; // x_j != xi_i => sub != 0
            coeff *= x_j * &sub.invert().unwrap(); //
        }
    }

    coeff
}

/// Locally combine list of t partial signatures into a final signature
fn combine_partial_signature(
    partial_signatures: Vec<PS>,
    t: usize,
) -> Result<Signature, SignError> {
    if partial_signatures.len() != t {
        return Err(SignError::FailedCheck(
            "Invalid number of partial signatures",
        ));
    }

    let final_session_id = partial_signatures[0].final_session_id;
    let public_key = partial_signatures[0].public_key;
    let message_hash = partial_signatures[0].message_hash;
    let r = partial_signatures[0].r;

    let mut sum_s_0 = Scalar::ZERO;
    let mut sum_s_1 = Scalar::ZERO;
    for partial_sign in partial_signatures.into_iter() {
        let cond = (partial_sign.final_session_id != final_session_id)
            || (partial_sign.public_key != public_key)
            || (partial_sign.r != r)
            || (partial_sign.message_hash != message_hash);
        if cond {
            return Err(SignError::FailedCheck(
                "Invalid list of partial signatures",
            ));
        }
        sum_s_0 += partial_sign.s_0;
        sum_s_1 += partial_sign.s_1;
    }

    let r = r.to_affine().x();
    let sum_s_1_inv = sum_s_1.invert().unwrap();
    let s = sum_s_0 * sum_s_1_inv;

    let sign = Signature::from_scalars(r, s)?;
    let sign = sign.normalize_s().unwrap_or(sign);

    VerifyingKey::from_affine(public_key.to_affine())?
        .verify_prehash(&message_hash, &sign)?;

    Ok(sign)
}

/// Get the additive offset of a key share for a given derivation path
pub fn derive_with_offset(
    public_key: &ProjectivePoint,
    root_chain_code: &[u8; 32],
    chain_path: &DerivationPath,
) -> Result<(Scalar, ProjectivePoint), BIP32Error> {
    let mut pubkey = *public_key;
    let mut chain_code = *root_chain_code;
    let mut additive_offset = Scalar::ZERO;
    for child_num in chain_path {
        let (il_int, child_pubkey, child_chain_code) =
            derive_child_pubkey(&pubkey, chain_code, child_num)?;
        pubkey = child_pubkey;
        chain_code = child_chain_code;
        additive_offset += il_int;
    }

    // Perform the mod q operation to get the additive offset
    Ok((additive_offset, pubkey))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    use crate::dkg::tests::{check_serde, dkg, dkg_inner};

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
                .filter(|msg| msg.from_id != party.keyshare.party_id)
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
                    .filter(|msg| msg.from_id != party.keyshare.party_id)
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
    fn sign_2_out_of_3_and_rotate_keyshares() {
        let mut rng = rand::thread_rng();

        let shares = dkg(3, 2);
        dsg(&shares[..2]);

        let rotation_states = shares
            .iter()
            .map(|s| crate::dkg::State::key_rotation(s, &mut rng))
            .collect::<Vec<_>>();

        let mut new_shares = dkg_inner(rotation_states);

        new_shares.iter_mut().zip(shares).for_each(
            |(new_share, old_share)| {
                new_share.finish_key_rotation(old_share).unwrap()
            },
        );

        // let's be creative and choose different set of shares
        dsg(&new_shares[1..]);
    }
}
