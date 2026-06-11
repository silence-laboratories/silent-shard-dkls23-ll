// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

mod common;

use wasm_bindgen_test::wasm_bindgen_test;

use common::run_vrf_dkg;

#[wasm_bindgen_test]
fn vrf_dkg_2_out_of_3() {
    let shares = run_vrf_dkg(3, 2);
    assert_eq!(shares.len(), 3);
    assert_eq!(
        shares[0].public_key().to_vec(),
        shares[1].public_key().to_vec()
    );
}
