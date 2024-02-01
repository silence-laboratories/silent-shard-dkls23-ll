use serde::{de::DeserializeOwned, Serialize};

use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

pub trait MessageRouting {
    fn src_party_id(&self) -> u8;
    fn dst_party_id(&self) -> Option<u8>;
}

#[wasm_bindgen]
pub struct Message {
    /// Source party ID
    pub from_id: u8,
    /// Destination party ID or undefined for broadcast messages
    pub to_id: Option<u8>,

    payload: Uint8Array,
}

#[wasm_bindgen]
impl Message {
    /// Payload
    #[wasm_bindgen(getter)]
    pub fn payload(&self) -> Uint8Array {
        let len = self.payload.length();
        self.payload.subarray(0, len)
    }

    #[wasm_bindgen(constructor)]
    pub fn create(payload: Uint8Array, from: u8, to: Option<u8>) -> Self {
        Self {
            from_id: from,
            to_id: to,
            payload,
        }
    }

    #[wasm_bindgen]
    pub fn clone(&self) -> Message {
        let len = self.payload.length();
        Message {
            from_id: self.from_id,
            to_id: self.to_id,
            payload: self.payload.subarray(0, len),
        }
    }
}

impl Message {
    pub fn new<T: Serialize + MessageRouting>(payload: T) -> Self {
        let mut buffer = vec![];
        ciborium::into_writer(&payload, &mut buffer)
            .expect_throw("CBOR encode error");

        let from_id = payload.src_party_id();
        let to_id = payload.dst_party_id();
        Self {
            from_id,
            to_id,
            payload: Uint8Array::from(buffer.as_ref()),
        }
    }

    pub fn decode<T: DeserializeOwned>(&self) -> T {
        let buffer = self.payload.to_vec();
        // TODO implement Read for Uint8Array ?
        ciborium::from_reader(&buffer as &[u8]).expect_throw("CBOR decode")
    }

    pub fn decode_vector<T: DeserializeOwned>(input: &[Self]) -> Vec<T> {
        input.iter().map(Self::decode).collect()
    }

    pub fn encode_vector<T: Serialize + MessageRouting>(
        msgs: Vec<T>,
    ) -> Vec<Self> {
        msgs.into_iter().map(|msg| Self::new(msg)).collect()
    }
}
