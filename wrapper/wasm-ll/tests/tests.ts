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

    let msg1: Message[] = parties.map(p => p.createFirstMessage());
    let msg2: Message[] = parties.flatMap((p, pid) => p.handleMessages(filterMessages(msg1, pid)));

    // after handling batch msg1, all parties calculate final session id,
    // and not we have to calculate commitments for chain_code_sid
    let commitments = parties.map(p => p.calculateChainCodeCommitment());

    let msg3: Message[] = parties.flatMap((p, pid) => p.handleMessages(selectMessages(msg2, pid)));
    let msg4: Message[] = parties.flatMap((p, pid) => p.handleMessages(selectMessages(msg3, pid), commitments));

    parties.flatMap((p, pid) => p.handleMessages(filterMessages(msg4, pid)));

    return parties.map(p => p.keyshare());
}


test('DKG 3x2', async () => {
    let shares = dkg(3, 2);
    console.log(shares);


});


test('DKG 2x2', async () => {
    let shares = dkg(2, 2);
    console.log(shares);


});


test('DSG 3x2', async () => {
    let shares = dkg(3, 2);

    let parties: SignSession[] = [];
    for (let i = 0; i < 2; i++) {
        parties.push(new SignSession(shares[i], "m"));
    }

    let msg1: Message[] = parties.map(p => p.createFirstMessage());
    // parties = saveRestore(parties);

    let msg2: Message[] = parties.flatMap((p, pid) => p.handleMessages(filterMessages(msg1, pid)));

    let msg3: Message[] = parties.flatMap((p, pid) => p.handleMessages(selectMessages(msg2, pid)));

    //p contains the presignatures
    parties.flatMap((p, pid) => p.handleMessages(selectMessages(msg3, pid)));

    let messageHash = new Uint8Array(32);

    let msg4: Message[] = parties.map(p => p.lastMessage(messageHash));

    //each element of signature[] contains the signature computed by each party
    let signatures = parties.map((p, pid) => p.combine(filterMessages(msg4, pid)));

    console.log(signatures);

});
