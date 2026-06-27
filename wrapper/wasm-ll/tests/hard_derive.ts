// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

// Requires a web build with the vrf feature (from wrapper/wasm-ll):
//   wasm-pack build -t web --features vrf
// Run (needs read access to load pkg/*.wasm):
//   deno test -A tests/hard_derive.ts

import {
  assert,
  assertEquals,
} from "https://deno.land/std@0.224.0/assert/mod.ts";

import initDkls from "../pkg/dkls_wasm_ll.js";
import {
  HardDeriveSession,
  KeygenSession,
  Keyshare,
  Message,
  SignSession,
  VrfKeygenSession,
  VrfKeyshare,
} from "../pkg/dkls_wasm_ll.js";

export const test = (name: string, f: (t: Deno.TestContext) => void | Promise<void>) => {
  Deno.test(name, async (t) => {
    await initDkls();
    return f(t);
  });
};

function filterMessages(msgs: Message[], party: number): Message[] {
  return msgs.filter((m) => m.from_id != party).map((m) => m.clone());
}

function selectMessages(msgs: Message[], party: number): Message[] {
  return msgs.filter((m) => m.to_id == party).map((m) => m.clone());
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

function signaturesEqual(sig1: unknown[], sig2: unknown[]): boolean {
  if (sig1.length !== sig2.length) {
    return false;
  }
  for (let i = 0; i < sig1.length; i++) {
    const a = sig1[i] as Uint8Array;
    const b = sig2[i] as Uint8Array;
    if (!bytesEqual(a, b)) {
      return false;
    }
  }
  return true;
}

function dkg(n: number, t: number): Keyshare[] {
  const parties: KeygenSession[] = [];
  for (let i = 0; i < n; i++) {
    parties.push(new KeygenSession(n, t, i));
  }

  const msg1: Message[] = parties.map((p) => p.createFirstMessage());
  const msg2: Message[] = parties.flatMap((p, pid) =>
    p.handleMessages(filterMessages(msg1, pid))
  );
  const msg3: Message[] = parties.flatMap((p, pid) =>
    p.handleMessages(selectMessages(msg2, pid))
  );
  const commitments = parties.map((p) => p.calculateChainCodeCommitment());
  const msg4: Message[] = parties.flatMap((p, pid) =>
    p.handleMessages(selectMessages(msg3, pid), commitments)
  );
  parties.flatMap((p, pid) => p.handleMessages(filterMessages(msg4, pid)));

  return parties.map((p) => p.keyshare());
}

function vrfDkg(n: number, t: number): VrfKeyshare[] {
  const parties: VrfKeygenSession[] = [];
  for (let partyId = 0; partyId < n; partyId++) {
    parties.push(new VrfKeygenSession(n, t, partyId));
  }

  const msg1: Message[] = parties.map((p) => p.createFirstMessage());
  const msg2: Message[] = parties.flatMap((p, pid) =>
    p.handleMessages(filterMessages(msg1, pid))
  );

  for (const party of parties) {
    party.handleMessages(msg2.map((m) => m.clone()));
  }

  return parties.map((p) => p.vrfKeyshare());
}

function hardDerive(
  threshold: number,
  rootShares: Keyshare[],
  vrfShares: VrfKeyshare[],
  path: Uint8Array,
): Keyshare[] {
  const sessions: HardDeriveSession[] = [];
  for (let i = 0; i < threshold; i++) {
    sessions.push(new HardDeriveSession(rootShares[i], vrfShares[i], path));
  }

  const round0: Message[] = sessions.map((s) => s.createFirstMessage());
  const round1: Message[] = sessions.flatMap((s) =>
    s.handleMessages(round0.map((m) => m.clone()))
  );
  assertEquals(round1.length, threshold);

  for (const session of sessions) {
    const outgoing = session.handleMessages(round1.map((m) => m.clone()));
    assertEquals(outgoing.length, 0, "hard derive should finish after round 2");
  }

  assert(
    sessions.every((s) => s.isFinished()),
    "hard derive stalled",
  );

  return sessions.map((s) => s.keyshare());
}

function dsg(shares: Keyshare[], t: number, messageHash: Uint8Array): unknown[][] {
  const parties: SignSession[] = [];
  for (let i = 0; i < t; i++) {
    parties.push(new SignSession(shares[i], "m"));
  }

  const msg1: Message[] = parties.map((p) => p.createFirstMessage());
  const msg2: Message[] = parties.flatMap((p, pid) =>
    p.handleMessages(filterMessages(msg1, pid))
  );
  const msg3: Message[] = parties.flatMap((p, pid) =>
    p.handleMessages(selectMessages(msg2, pid))
  );
  parties.flatMap((p, pid) => p.handleMessages(selectMessages(msg3, pid)));

  const msg4: Message[] = parties.map((p) => p.lastMessage(messageHash));
  return parties.map((p, pid) => p.combine(filterMessages(msg4, pid)));
}

test("hard derive and sign 2 out of 3", async () => {
  const PARTICIPANTS = 3;
  const THRESHOLD = 2;
  const PATH = new TextEncoder().encode("hard-derive/wasm-test");

  const rootShares = dkg(PARTICIPANTS, THRESHOLD);
  const vrfShares = vrfDkg(PARTICIPANTS, THRESHOLD);
  const derived = hardDerive(THRESHOLD, rootShares, vrfShares, PATH);

  assertEquals(derived.length, THRESHOLD);
  assert(
    !bytesEqual(derived[0].publicKey, rootShares[0].publicKey),
    "derived public key must differ from root",
  );

  const messageHash = new Uint8Array(32).fill(7);
  const signatures = dsg(derived, THRESHOLD, messageHash);
  assertEquals(signatures.length, THRESHOLD);

  for (const sig of signatures.slice(1)) {
    assert(signaturesEqual(signatures[0], sig));
  }

  const r = signatures[0][0] as Uint8Array;
  const s = signatures[0][1] as Uint8Array;
  assertEquals(r.length, 32);
  assertEquals(s.length, 32);
});
