// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

use k256::elliptic_curve::group::GroupEncoding;

use dkls23_ll::dkg;

// use bincode::serde::{decode_from_slice, encode_to_vec};

#[wasm_bindgen]
pub struct Keyshare {
    inner: dkg::Keyshare,
}

impl Keyshare {
    pub fn new(inner: dkg::Keyshare) -> Self {
        Self { inner }
    }

    pub fn into_inner(self) -> dkg::Keyshare {
        self.inner
    }
}

impl AsRef<dkg::Keyshare> for Keyshare {
    fn as_ref(&self) -> &dkg::Keyshare {
        &self.inner
    }
}

#[wasm_bindgen]
impl Keyshare {
    /// Create an instance of keyshare from passed array of bytes.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Keyshare, JsError> {
        let inner = ciborium::from_reader(bytes).expect_throw("CBOR decode");

        Ok(Keyshare { inner })
    }

    /// Serialize keyshare into array of bytes.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = vec![];
        ciborium::into_writer(&self.inner, &mut buffer)
            .expect_throw("CBOR encode error");
        buffer
    }

    #[wasm_bindgen(js_name = publicKey, getter)]
    pub fn public_key(&self) -> Uint8Array {
        let bytes = self.inner.public_key.to_bytes();

        Uint8Array::from(bytes.as_ref())
    }

    #[wasm_bindgen(js_name = participants, getter)]
    pub fn participants(&self) -> u8 {
        self.inner.rank_list.len() as u8
    }

    #[wasm_bindgen(js_name = threshold, getter)]
    pub fn threshold(&self) -> u8 {
        self.inner.threshold
    }

    #[wasm_bindgen(js_name = partyId, getter)]
    pub fn party_id(&self) -> u8 {
        self.inner.party_id
    }

    /// Depricated method, the method does nothing.
    /// It exists for backward compatibility only
    #[wasm_bindgen(js_name = finishKeyRotation)]
    pub fn finish_key_rotation(&mut self, _oldshare: Keyshare) {
        // empty!
    }
}
