use js_sys::{Error, Reflect};
use wasm_bindgen::{prelude::*, throw_str};

use dkls23_ll::{dkg::KeygenError, dsg::SignError};

fn set_party_id(js_err: &js_sys::Error, prop: &str, party_id: u8) {
    let ok = Reflect::set(
        js_err,
        &JsValue::from_str(prop),
        &JsValue::from_f64(party_id as _),
    );

    if ok != Ok(true) {
        throw_str("expect to set property on an error object");
    }
}

pub fn keygen_error(err: KeygenError) -> js_sys::Error {
    Error::new(&err.to_string())
}

pub fn sign_error(err: SignError) -> js_sys::Error {
    let js_err = Error::new(&err.to_string());

    if let SignError::AbortProtocolAndBanParty(p) = err {
        set_party_id(&js_err, "banParty", p);
    }

    js_err
}
