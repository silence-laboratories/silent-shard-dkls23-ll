// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use rand::prelude::*;
use rand_chacha::ChaCha20Rng;

use wasm_bindgen::prelude::*;

mod errors;
mod keygen;
mod keyshare;
mod message;
mod sign;
mod sign_ot_variant;
mod utils;

#[cfg(feature = "vrf")]
mod hard_derive;
#[cfg(feature = "vrf")]
mod vrf_keygen;
#[cfg(feature = "vrf")]
mod vrf_keyshare;
#[cfg(feature = "vrf")]
mod vrf_session;

pub use keygen::KeygenSession;
pub use keyshare::Keyshare;
pub use message::Message;
pub use sign::SignSession;
pub use sign_ot_variant::SignSessionOTVariant;

#[cfg(feature = "vrf")]
pub use hard_derive::HardDeriveSession;
#[cfg(feature = "vrf")]
pub use vrf_keygen::VrfKeygenSession;
#[cfg(feature = "vrf")]
pub use vrf_keyshare::VrfKeyshare;

pub fn maybe_seeded_rng<T: AsRef<[u8]>>(seed: Option<T>) -> ChaCha20Rng {
    let seed = match seed.as_ref() {
        None => rand::thread_rng().gen(),
        Some(seed) => {
            seed.as_ref().try_into().expect_throw("invalid seed size")
        }
    };

    ChaCha20Rng::from_seed(seed)
}
