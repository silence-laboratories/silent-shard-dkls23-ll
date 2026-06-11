// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::sync::Arc;

use curve25519_dalek::RistrettoPoint;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

use dkls23_ll::vrf::VrfKeyshare as InnerVrfKeyshare;

#[wasm_bindgen]
pub struct VrfKeyshare {
    inner: Arc<InnerVrfKeyshare>,
}

impl VrfKeyshare {
    pub(crate) fn new(inner: InnerVrfKeyshare) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }

    pub(crate) fn as_inner(&self) -> &InnerVrfKeyshare {
        self.inner.as_ref()
    }
}

#[wasm_bindgen]
impl VrfKeyshare {
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<VrfKeyshare, JsError> {
        let inner: InnerVrfKeyshare =
            ciborium::from_reader(bytes).expect_throw("CBOR decode error");
        Ok(VrfKeyshare::new(inner))
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = vec![];
        ciborium::into_writer(self.inner.as_ref(), &mut buffer)
            .expect_throw("CBOR encode error");
        buffer
    }

    #[wasm_bindgen(js_name = publicKey, getter)]
    pub fn public_key(&self) -> Uint8Array {
        let bytes = compress_point(self.inner.public_key());
        Uint8Array::from(bytes.as_ref())
    }

    #[wasm_bindgen(getter, js_name = threshold)]
    pub fn threshold(&self) -> u8 {
        self.inner.threshold
    }

    #[wasm_bindgen(getter, js_name = participants)]
    pub fn participants(&self) -> u8 {
        self.inner.total_parties
    }

    #[wasm_bindgen(getter, js_name = partyId)]
    pub fn party_id(&self) -> u8 {
        self.inner.party_id
    }

    #[wasm_bindgen(getter, js_name = keyId)]
    pub fn key_id(&self) -> Vec<u8> {
        self.inner.key_id.to_vec()
    }

    #[wasm_bindgen(getter, js_name = rootChainCode)]
    pub fn root_chain_code(&self) -> Vec<u8> {
        self.inner.root_chain_code.to_vec()
    }
}

fn compress_point(point: &RistrettoPoint) -> [u8; 32] {
    point.compress().to_bytes()
}
