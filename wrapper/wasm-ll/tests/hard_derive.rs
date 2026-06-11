// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Root DKG → VRF DKG → hard derivation → sign on derived key.

mod common;

use js_sys::Uint8Array;
use k256::{
    ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey},
    elliptic_curve::ops::Reduce,
    Scalar, U256,
};
use wasm_bindgen::JsCast;
use wasm_bindgen_test::wasm_bindgen_test;

use common::{
    run_dkg, run_dsg, run_hard_derive, run_vrf_dkg, signatures_equal,
};

#[wasm_bindgen_test]
fn hard_derive_and_sign_2_out_of_3() {
    const PARTICIPANTS: u8 = 3;
    const THRESHOLD: u8 = 2;
    const PATH: &[u8] = b"hard-derive/wasm-test";

    let root_shares = run_dkg(PARTICIPANTS, THRESHOLD);
    let vrf_shares = run_vrf_dkg(PARTICIPANTS, THRESHOLD);
    let derived = run_hard_derive(THRESHOLD, &root_shares, &vrf_shares, PATH);

    assert_eq!(derived.len(), THRESHOLD as usize);
    assert_ne!(
        derived[0].public_key().to_vec(),
        root_shares[0].public_key().to_vec(),
        "derived public key must differ from root"
    );

    let message_hash = vec![7u8; 32];
    let signatures = run_dsg(&derived, THRESHOLD as usize, &message_hash);
    assert_eq!(signatures.len(), THRESHOLD as usize);

    let sig0 = &signatures[0];
    for sig in &signatures[1..] {
        assert!(signatures_equal(sig0, sig));
    }

    let r = signatures[0].get(0).dyn_into::<Uint8Array>().unwrap();
    let s = signatures[0].get(1).dyn_into::<Uint8Array>().unwrap();
    let r_scalar = Scalar::reduce(U256::from_be_slice(&r.to_vec()));
    let s_scalar = Scalar::reduce(U256::from_be_slice(&s.to_vec()));
    let signature = Signature::from_scalars(r_scalar, s_scalar)
        .expect("invalid signature");
    let verifying_key =
        VerifyingKey::from_sec1_bytes(&derived[0].public_key().to_vec())
            .expect("invalid verifying key");

    verifying_key
        .verify_prehash(&message_hash, &signature)
        .expect("signature verification failed");
}
