// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use rand::prelude::*;
use rand_chacha::ChaCha20Rng;

use wasm_bindgen::prelude::*;

mod keygen;
mod keyshare;
mod message;
mod sign;
mod utils;

pub fn maybe_seeded_rng<T: AsRef<[u8]>>(seed: Option<T>) -> ChaCha20Rng {
    let seed = match seed.as_ref() {
        None => rand::thread_rng().gen(),
        Some(seed) => {
            seed.as_ref().try_into().expect_throw("invalid seed size")
        }
    };

    ChaCha20Rng::from_seed(seed)
}
