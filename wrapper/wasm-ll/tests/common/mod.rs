// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

#![allow(dead_code)]

use js_sys::{Array, Uint8Array};
use wasm_bindgen::JsCast;

use dkls_wasm_ll::{
    HardDeriveSession, KeygenSession, Keyshare, Message, SignSession,
    VrfKeygenSession, VrfKeyshare,
};

pub fn filter_messages(msgs: &[Message], party_id: u8) -> Vec<Message> {
    msgs.iter()
        .filter(|msg| msg.from_id != party_id)
        .cloned()
        .collect()
}

pub fn select_messages(msgs: &[Message], party_id: u8) -> Vec<Message> {
    msgs.iter()
        .filter(|msg| msg.to_id == Some(party_id))
        .cloned()
        .collect()
}

pub fn run_dkg(n: u8, t: u8) -> Vec<Keyshare> {
    let mut parties: Vec<KeygenSession> =
        (0..n).map(|i| KeygenSession::new(n, t, i, None)).collect();

    let msg1: Vec<Message> = parties
        .iter_mut()
        .map(|p| p.create_first_message().unwrap())
        .collect();

    let mut msg2: Vec<Message> = Vec::new();
    for (i, party) in parties.iter_mut().enumerate() {
        let batch = filter_messages(&msg1, i as u8);
        msg2.extend(party.handle_messages(batch, None, None).unwrap());
    }

    let mut msg3: Vec<Message> = Vec::new();
    for (i, party) in parties.iter_mut().enumerate() {
        let batch = select_messages(&msg2, i as u8);
        msg3.extend(party.handle_messages(batch, None, None).unwrap());
    }

    let commitments: Array = parties
        .iter()
        .map(|p| Uint8Array::from(p.calculate_commitment_2().as_ref()))
        .collect::<Array>();

    let mut msg4: Vec<Message> = Vec::new();
    for (i, party) in parties.iter_mut().enumerate() {
        let batch = select_messages(&msg3, i as u8);
        msg4.push(
            party
                .handle_messages(batch, Some(commitments.clone()), None)
                .unwrap()
                .pop()
                .unwrap(),
        );
    }

    for (i, party) in parties.iter_mut().enumerate() {
        let batch = filter_messages(&msg4, i as u8);
        party.handle_messages(batch, None, None).unwrap();
    }

    parties.into_iter().map(|p| p.keyshare().unwrap()).collect()
}

pub fn run_vrf_dkg(n: u8, t: u8) -> Vec<VrfKeyshare> {
    let mut parties: Vec<VrfKeygenSession> = (0..n)
        .map(|party_id| VrfKeygenSession::new(n, t, party_id, None).unwrap())
        .collect();

    let msg1: Vec<Message> = parties
        .iter_mut()
        .map(|p| p.create_first_message(None).unwrap())
        .collect();

    let mut msg2: Vec<Message> = Vec::new();
    for (i, party) in parties.iter_mut().enumerate() {
        let batch = filter_messages(&msg1, i as u8);
        msg2.extend(party.handle_messages(batch, None).unwrap());
    }

    for party in parties.iter_mut() {
        let batch = msg2.clone();
        party.handle_messages(batch, None).unwrap();
    }

    parties
        .into_iter()
        .map(|p| p.vrf_keyshare().unwrap())
        .collect()
}

pub fn run_hard_derive(
    threshold: u8,
    root_shares: &[Keyshare],
    vrf_shares: &[VrfKeyshare],
    path: &[u8],
) -> Vec<Keyshare> {
    let t = threshold as usize;
    let path = path.to_vec();

    let mut sessions: Vec<HardDeriveSession> = (0..t)
        .map(|i| {
            HardDeriveSession::new(
                &root_shares[i],
                &vrf_shares[i],
                path.clone(),
                None,
            )
            .unwrap()
        })
        .collect();

    let round0: Vec<Message> = sessions
        .iter_mut()
        .map(|session| session.create_first_message().unwrap())
        .collect();

    let round1: Vec<Message> = sessions
        .iter_mut()
        .flat_map(|session| {
            let inputs = round0.clone();
            session.handle_messages(inputs, None).unwrap()
        })
        .collect();

    assert_eq!(round1.len(), t);

    for session in sessions.iter_mut() {
        let inputs = round1.clone();
        let outgoing = session.handle_messages(inputs, None).unwrap();
        assert!(
            outgoing.is_empty(),
            "hard derive should finish after round 2"
        );
    }

    assert!(
        sessions.iter().all(|session| session.is_finished()),
        "hard derive stalled"
    );

    sessions
        .into_iter()
        .map(|session| session.keyshare().unwrap())
        .collect()
}

pub fn run_dsg(
    shares: &[Keyshare],
    t: usize,
    message_hash: &[u8],
) -> Vec<Array> {
    let mut parties: Vec<SignSession> = shares[..t]
        .iter()
        .map(|share| SignSession::new(share.clone(), "m", None))
        .collect();

    let msg1: Vec<Message> = parties
        .iter_mut()
        .map(|p| p.create_first_message().unwrap())
        .collect();

    let mut msg2: Vec<Message> = Vec::new();
    for (i, party) in parties.iter_mut().enumerate() {
        let batch = filter_messages(&msg1, i as u8);
        msg2.extend(party.handle_messages(batch, None).unwrap());
    }

    let mut msg3: Vec<Message> = Vec::new();
    for (i, party) in parties.iter_mut().enumerate() {
        let batch = select_messages(&msg2, i as u8);
        msg3.extend(party.handle_messages(batch, None).unwrap());
    }

    for (i, party) in parties.iter_mut().enumerate() {
        let batch = select_messages(&msg3, i as u8);
        party.handle_messages(batch, None).unwrap();
    }

    let msg4: Vec<Message> = parties
        .iter_mut()
        .map(|p| p.last_message(message_hash).unwrap())
        .collect();

    parties
        .into_iter()
        .enumerate()
        .map(|(i, party)| {
            let batch = filter_messages(&msg4, i as u8);
            party.combine_partial_signature(batch).unwrap()
        })
        .collect()
}

pub fn signatures_equal(sig1: &Array, sig2: &Array) -> bool {
    if sig1.length() != sig2.length() {
        return false;
    }

    for i in 0..sig1.length() {
        let arr1 = sig1.get(i).dyn_into::<Uint8Array>().unwrap();
        let arr2 = sig2.get(i).dyn_into::<Uint8Array>().unwrap();
        if arr1.to_vec() != arr2.to_vec() {
            return false;
        }
    }

    true
}
