// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

// to run tests we need web build
// wasm-pack build -t web ..

import { assertEquals, assertThrows } from "https://deno.land/std@0.224.0/assert/mod.ts";

import initDkls from '../pkg/dkls_wasm_ll.js';
import {KeygenSession, Keyshare} from '../pkg/dkls_wasm_ll.js';
import {SignSession, Message} from '../pkg/dkls_wasm_ll.js';


export const test = (name: string, f: any) => {
    Deno.test(name, async (t) => {
        await initDkls();
        return f(t);
    });
};

function saveRestore(parties: KeygenSession[]): KeygenSession[] {
    let bytes = parties.map((p) => {
        let b = p.toBytes();
        p.free(); // deallocate the object on Rust side
        return b;
    });

    return bytes.map(b => KeygenSession.fromBytes(b));
}

function copyKeyshare(share: Keyshare): Keyshare {
    return Keyshare.fromBytes(share.toBytes());
}

function filterMessages(msgs: Message[], party: number): Message[] {
    return msgs.filter((m) => m.from_id != party).map(m => m.clone());
}

function selectMessages(msgs: Message[], party: number): Message[] {
    return msgs.filter((m) => m.to_id == party).map(m => m.clone());
}

function dkg(n: number, t: number): Keyshare[] {
    let parties: KeygenSession[] = [];

    for (let i = 0; i < n; i++) {
        parties.push(new KeygenSession(n, t, i));
    }

    return dkg_inner(parties);
}

function initKeyRotation(oldshares: Keyshare[]) {
    return oldshares.map(p => KeygenSession.initKeyRotation(p));
}

function dkg_inner(parties: KeygenSession[]): Keyshare[] {
    let msg1: Message[] = parties.map(p => p.createFirstMessage());
    let msg2: Message[] = parties.flatMap((p, pid) => p.handleMessages(filterMessages(msg1, pid)));

    // after handling batch msg1, all parties calculate final session id,
    // and not we have to calculate commitments for chain_code_sid
    let commitments = parties.map(p => p.calculateChainCodeCommitment());

    let msg3: Message[] = parties.flatMap((p, pid) => p.handleMessages(selectMessages(msg2, pid)));
    let msg4: Message[] = parties.flatMap((p, pid) => p.handleMessages(selectMessages(msg3, pid), commitments));

    parties.flatMap((p, pid) => p.handleMessages(filterMessages(msg4, pid)));

    return parties.map(p => p.keyshare()); // deallocates session object
}

function dsg(shares: Keyshare[], t: number, messageHash: Uint8Array) {
    let parties: SignSession[] = [];

    // for simplicity we always use the first T shares.
    for(let i = 0; i < t; i++) {
        parties.push(new SignSession(shares[i], "m"));
    }

    let msg1: Message[] = parties.map(p => p.createFirstMessage());
    let msg2: Message[] = parties.flatMap((p, pid) => p.handleMessages(filterMessages(msg1, pid)));
    let msg3: Message[] = parties.flatMap((p, pid) => p.handleMessages(selectMessages(msg2, pid)));

    parties.flatMap((p, pid) => p.handleMessages(selectMessages(msg3, pid)));

    let msg4: Message[] = parties.map(p => p.lastMessage(messageHash));

    let signs = parties.map((p, pid) => p.combine(filterMessages(msg4, pid)));

    return signs;
}

test('DKG 3x2', async () => {
    let shares = dkg(3,2);
});


test('DKG 2x2', async () => {
    let shares = dkg(2,2);
});

test('DKG 3x3', async () => {
    let shares = dkg(3,3);
});

test('DKG 4x3', async () => {
    let shares = dkg(4,3);
});

test('DSG 2x2', async () => {
    let shares = dkg(2, 2);

    dsg(shares, 2, new Uint8Array(32));
});

test('DSG 3x2', async () => {
    let shares = dkg(3, 2);

    dsg(shares, 2, new Uint8Array(32));
});

test('DSG 3x3', async () => {
    let shares = dkg(3, 3);

    dsg(shares, 3, new Uint8Array(32));
});

test('DSG 4x3', async () => {
    let shares = dkg(4, 3);

    dsg(shares, 3, new Uint8Array(32));
});

test('DSG 5x3', async () => {
    let shares = dkg(5, 3);

    dsg(shares, 3, new Uint8Array(32));
});

test('Key rotation', async() => {
    let messageHash = new Uint8Array(32);

    let shares = dkg(3, 2); // create initial key shares;

    // new SignSession(share, chainPath) consumes passed share
    // so we have to make a copy to use shares again in key rotation
    let signs = dsg(shares.map(s => copyKeyshare(s)), 2, messageHash);

    let rotation_parties = initKeyRotation(shares);
    let new_shares = dkg_inner(rotation_parties);

    // this call is not necessary, it is here only to test backward
    // compatibility
    new_shares.forEach((s, i) => s.finishKeyRotation(shares[i]));

    let new_signs = dsg(new_shares, 2, messageHash);
});

test('DKG session should fail', () => {

    let s = new KeygenSession(3, 2, 1);
    let m = s.createFirstMessage();

    assertThrows(() => s.createFirstMessage())

    assertThrows(() => s.handleMessages([m]));
});

test('DSG session should fail', () => {
    // run DKG to get a key shares
    let shares = dkg(3,2);

    let s = new SignSession(shares[0], "m");
    let m = s.createFirstMessage();

    // trying to create first message more then
    // one should fail.
    assertThrows(() => s.createFirstMessage())

    // passing a message create by a session to
    // the same session should fail.
    assertThrows(() => s.handleMessages([m]));
});

test('key share recovery', () => {
    let s = dkg(3,2);

    let lost_key_shares = Uint8Array.from([0]);
    let pk = s[0].publicKey;

    let parties = [
        KeygenSession.initLostShareRecovery(3, 2, 0, pk, lost_key_shares),
        KeygenSession.initKeyRecovery(s[1], lost_key_shares),
        KeygenSession.initKeyRecovery(s[2], lost_key_shares),
    ];

    let new_shares = dkg_inner(parties);

    let new_pk = new_shares[0].publicKey;

    assertEquals(pk, new_pk);

    // make sure we could generate a signature using new shares
    let messageHash = Uint8Array.from({length: 32}, () => Math.floor(Math.random() * 255));
    let new_signs = dsg(new_shares, 2, messageHash);
});
