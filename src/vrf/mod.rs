// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Threshold MPC VRF support for DKLS23 signing keys.
//!
//! VRF keys live on Ristretto (Shamir DKG, Protocol 12). Hard derivation combines
//! VRF eval output with DKLS23 secp256k1 root keyshares via [`sl_mpc_derive`].

pub mod dkg;
pub mod eval;
pub mod hard_derivation;
mod hard_derive_root;
pub mod messages;
mod types;

pub use dkg::{
    Party as VrfDkgParty, State as VrfDkgState, VrfKeygenError,
    VrfKeygenMsg1, VrfKeygenMsg2, VrfKeyshare,
};
pub use eval::{State as VrfEvalState, VrfOutput};
pub use hard_derivation::{
    keyshare_after_hard_derive, HardDeriveError, HardDeriveMsg0,
    HardDeriveMsg1, MpcDeriveInit, State as HardDeriveState,
};
pub use hard_derive_root::{apply_hard_derive_dkls, DklsHardDeriveRoot};
pub use messages::{VrfMsg0, VrfMsg1};
pub use types::VrfError;
