# Multi-Party-TSS (ECDSA-DKLs23)

**Silent Shard** uses
Multiparty computation (MPC) and enables a set of parties that do
not trust each other to jointly compute a secret signing key without
being constructed in one place and an ECDSA signature over their secret key shards
while not sharing them with any of the involved parties, removing single points of trust.

TSS consists of three stages:

- Distributed Key Generation (DKG),
- Distributed Signature Generation, and
- Proactive Security with Key rotation/refresh.

These functions involve cryptographic computing at the participating
nodes of the MPC quorum and exchanges of rounds of messages, which
ultimately lead to the generation of a valid signature at the
requested node. These computing nodes can be any device with
sufficient computational and memory capability, including but not
limited to smartphones, server nodes, and edge devices. The basic
philosophy behind Silent Shard remains that no single device holding
the private key can be used to generate signatures and move digital
assets. The private key is shared among multiple computing nodes so
that no party has any information about the key. Then, in order to
generate a signature, the threshold number of devices runs a secure
two-party computation protocol that generates the signature without
revealing anything about the parties' key shares to each other. These
devices may or may not be associated with the same person or
organization and can be any form factor. Thus, one could use this to
create a wallet, sharing the private key between one's mobile and
one's laptop, between one's mobile and a VM in the cloud, and so on.


# Protocol

- Silent Shard is based on the DKLs23 threshold signature scheme
- Enabled by a well-chosen correlation + simple new consistency check.
- Blackbox use of UC 2-round 2P-MUL. OT-based
  protocols satisfy UC, but AHE is more complicated.
- No (explicit) ZK proofs during signing or DKG; light protocol and
  straightforward UC analysis.

# Disclaimer
- The code does not handle network communication security.
- The state struct per request has public and private fields.
- Pre-signatures **should** be used only once.
- Proper validation of messages per round is needed.

# Installation

```shell
npm install @silencelaboratories/dkls-wasm-ll-node
```

# Important Data Objects

## Party ID

Each participant of DKG or DSG is identified by a party ID, a small
integer range [0..N-1], where N is the number of participants of some
particular protocol.

## Message

A message is an opaque array of bytes with two additional properties:
`from_id` and `to_id`. The caller should use from properties to route
messages to a receiver after encrypting and authenticating the message in transit.

```js
// Construct message from an array of bytes
new Message(payload: Uint8Array, from: number, to?: number);
```

## KeygenSession

Create a new distributed key generation session.

```js
// N - total number of participants
// T - threshold
function dkg(n: number, t: number): Keyshare[] {
    let parties: KeygenSession[] = [];

    // create KeygenSession for each party
    for (let i = 0; i < n; i++) {
        parties.push(new KeygenSession(n, t, i));
    }

    // execute DKG
    return dkg_inner(parties);
}

function dkg_inner(parties: KeygenSession[]): Keyshare[] {

    // Execution starts by creating the first message
    let msg1: Message[] = parties.map(p => p.createFirstMessage());

    // The following statement emulates message broadcasting and receiving
    // by each party, messages from all other parties. That is, if N = 3
    // then for party 0, we have to deliver messages from parties 1, 2.
    //
    // method handleMessage() will return a batch of P2P for each other
    // party, and we collect all messages in the msg2 array.
    //
    // Real code should encrypt each P2P message and use appropriate
    // network transport to communicate the message to a designated party
    // decrypt and pass to the next call of handleMessages().
    let msg2: Message[] = parties.flatMap((p, pid) => p.handleMessages(filterMessages(msg1, pid)));

    // after handling batch msg1, all parties calculate final session id,
    // and now we have to calculate commitments for chain_code_sid
    let commitments = parties.map(p => p.calculateChainCodeCommitment());

    // Select messages are designated for a particular party and handle them.
    // It will generate a batch of P2P messages.
    let msg3: Message[] = parties.flatMap((p, pid) => p.handleMessages(selectMessages(msg2, pid)));

    // handle P2P messages and generate the last round of broadcast messages.
    let msg4: Message[] = parties.flatMap((p, pid) => p.handleMessages(selectMessages(msg3, pid), commitments));

    // handle the last broadcast messages.
    parties.flatMap((p, pid) => p.handleMessages(filterMessages(msg4, pid)));

    // extract keyshare from session object and consume (deallocate) session object
    return parties.map(p => p.keyshare());
}

function filterMessages(msgs: Message[], party: number): Message[] {
    return msgs.filter((m) => m.from_id != party).map(m => m.clone());
}

function selectMessages(msgs: Message[], party: number): Message[] {
    return msgs.filter((m) => m.to_id == party).map(m => m.clone());
}

```

`KeygenSession` object is serializable. Use methods `.toBytes()` and
`.fromBytes()`.

Both `Keyshare` and `KeygenSession` need to be properly encrypted and authenticated.

## Key Rotation

A key rotation session is very similar to normal key generation.

```js
// Create a key rotation session
let session = KeygenSession.initKeyRotation(existingKeyShare);

// then perform key generation as shown above and get newKeyShare.
newKeyShare.finishKeyRotation(existingKeyShare);

// the call above will deallocate existingKeyShare and finish
// the key rotation protocol.

```



## SignSession
Create a sign session

```js

// shares is the output of dkg(3, 2).

function dsg(shares: Keyshare[], t: number, messageHash: Uint8Array) {
    let parties: SignSession[] = [];

    // for simplicity, we always use the first T shares.
    for(let i = 0; i < t; i++) {
        // new SignSession() consumes passed keyshare.
        parties.push(new SignSession(shares[i], "m"));
    }

    let msg1: Message[] = parties.map(p => p.createFirstMessage());

    // broadcast the first message to all parties.
    let msg2: Message[] = parties.flatMap((p, pid) => p.handleMessages(filterMessages(msg1, pid)));

    // handle the first message and generate the first P2P message for all parties.
    let msg3: Message[] = parties.flatMap((p, pid) => p.handleMessages(selectMessages(msg2, pid)));

    // handle the batch of P2P messages.
    parties.flatMap((p, pid) => p.handleMessages(selectMessages(msg3, pid)));

    // Now each party has a PreSignature. It does not depend on the message to be signed,
    // and the caller can generate a batch of pre-signatures ahead of time.
    //
    // Take a pre-signature and 32-byte hash of the message to sign, produce the last
    // broadcast message.
    //
    // The caller *MUST NOT USE A PRE-SIGNATURE MORE THAN ONCE*.
    //
    // *REUSE OF PRE-SIGNATURES LEADS TO PRIVATE KEY FULL EXPOSURE*.
    //
    let msg4: Message[] = parties.map(p => p.lastMessage(messageHash));

    // handle last round of broadcast messages and produce the signature.
    // method .combine() consumes (deallocates) session object.
    let signs = parties.map((p, pid) => p.combine(filterMessages(msg4, pid)));

    return signs;
}
```

## Memory Management

The `Message` object designates a memory buffer in the WASM heap. There is
no automatic memory management, and the caller is responsible for calling
`.free()` at the appropriate time.

Methods `.handleMessages()` consume passed-in messages. This means
that the caller has to call `.free()` methods only to deallocate objects
as part of error handling.

## Error Handling

session.handleMessages() may throw an error. It is not possible to
recover from this error.

In most cases, err.message only could help to debug an application.

One special case MUST be handled.

SignSession.handleMessages() could throw an error AbortProtocolAndBanParty.
In this case, the error object has a property "banParty", the value is
in the range [0 .. threshold-1]. Zero is a valid party ID!
