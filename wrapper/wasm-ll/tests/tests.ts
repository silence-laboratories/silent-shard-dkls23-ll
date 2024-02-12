// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

// to run tests we need web build
// wasm-pack build -t web ..

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

function key_rotation(oldshares: Keyshare[]) {
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


test('DSG 3x2', async () => {
    let shares = dkg(3, 2);

    dsg(shares, 2, new Uint8Array(32));
});

test('Key rotation', async() => {
    let messageHash = new Uint8Array(32);

    let shares = dkg(3, 2); // create initial key shares;

    // new SignSession(share, chainPath) consumes passed share
    // so we have to make a copy to use shares again in key rotation
    let signs = dsg(shares.map(s => copyKeyshare(s)), 2, messageHash);

    let rotation_parties = key_rotation(shares);
    let new_shares = dkg_inner(rotation_parties);

    new_shares.forEach((s, i) => s.finishKeyRotation(shares[i]));

    let new_signs = dsg(new_shares, 2, messageHash);
});
