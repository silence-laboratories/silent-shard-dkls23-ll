// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

mod common;

use wasm_bindgen_test::wasm_bindgen_test;

use common::run_vrf_dkg;

#[wasm_bindgen_test]
fn vrf_dkg_2_out_of_3() {
    let shares = run_vrf_dkg(3, 2);
    assert_eq!(shares.len(), 3);

    let pk0 = shares[0].public_key().to_vec();
    for share in &shares[1..] {
        assert_eq!(pk0, share.public_key().to_vec());
    }
}

#[wasm_bindgen_test]
fn vrf_keygen_session_roundtrip() {
    let mut session =
        dkls_wasm_ll::VrfKeygenSession::new(3, 2, 0, None).unwrap();
    let _ = session.create_first_message(None).unwrap();
    let restored =
        dkls_wasm_ll::VrfKeygenSession::from_bytes(&session.to_bytes());
    assert!(restored.error().is_none());
}
