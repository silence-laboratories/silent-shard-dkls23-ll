use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

use k256::elliptic_curve::group::GroupEncoding;

use dkls23_ll::dkg;

use bincode::serde::{decode_from_slice, encode_to_vec};

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

#[wasm_bindgen]
impl Keyshare {
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Keyshare, JsError> {
        let (inner, _): (dkg::Keyshare, _) = decode_from_slice(bytes, bincode::config::standard())
            .map_err(|_| JsError::new("keyshare decode error"))?;

        Ok(Keyshare { inner })
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_to_vec(&self.inner, bincode::config::standard())
            .expect_throw("keyshare encode error")
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
}
