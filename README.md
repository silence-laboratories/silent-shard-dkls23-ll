# Multi-Party-TSS (ECDSA-DKLs23)

**Silent Shard** uses Multiparty computation (MPC) and enables a set
of parties that do not trust each other to jointly compute a secret
signing key without being constructed in one place and an ECDSA
signature over their secret key shards while not sharing them with any
of the involved parties, removing single points of trust.

TSS consists of three stages:

- Distributed Key Generation (DKG),
- Distributed Signature Generation, and
- Proactive Security with Key rotation/refresh.

These functions involve cryptographic computing at the participating
nodes of the MPC quorum and exchanges of rounds of messages which
ultimately lead to the generation of a valid signature at the
requested node. These computing nodes can be any device with
sufficient computational and memory capability, including but not
limited to smartphones, server nodes, and edge devices. The basic
philosophy behind Silent Shard remains that no single device holding
the private key can be used to generate signatures and move digital
assets. The private key is shared among multiple computing nodes so
that no party has any information about the key. Then, in order to
generate a signature, the threshold number of devices run a secure
two-party computation protocol that generates the signature without
revealing anything about the parties' key shares to each other. These
devices may or may not be associated with the same person or
organization and can be any form factor. Thus, one could use this to
create a wallet, sharing the private key between one's mobile and
one's laptop, between one's mobile and a VM in the cloud, and so on.


# Protocol

- Silent Shard is based on DKLs23 threshold signature scheme
- Enabled by well-chosen correlation + simple new consistency check.
- Blackbox use of UC 2-round 2P-MUL.
- UC secure.

# Disclaimer

The suffix "ll" indicates these libraries are low-level. They provide
foundational building blocks for real-world applications but
intentionally exclude many crucial components typically required in
secure applications. By design, this scope focuses on providing a base
layer without incorporating features like message serialization,
protection against replay attacks, or key exchange mechanisms.

Users of these libraries are expected to implement the following:
- Message serialization
- Message deserialization and validation.
- Protection against message replay attacks
- Message **signing** for broadcast messages and a mechanism to certify
  verifying keys (e.g., X.509 certificates)
- Message **encryption** for peer-to-peer (P2P) messages, likely including
  a key exchange mechanism to derive symmetric encryption keys
- A secure random number generator
- Key share encryption
- Robust updates of key shares after key refresh
- Encrypted storage for pre-signatures that guarantees each
  pre-signature is used at **most once**.
- A system design allowing all parties to agree on input parameters
  for Multi-Party Computation (MPC) protocols.
- The consumer of the library should hash the message to be signed before calling the distributed dkls23.sign() protocol on input the hashed message to be signed.
 **Building a consumer stack which does not hash the message to be signed but instead accepts the message from client input and is passed as is to the underlying dkls23 library to sign is insecure as it can lead to forgeries.**
  to be insecure**.
- All necessary authorization and authentication mechanisms.


# Crates

## dksl23-ll

The library contains a small set of tests. Please look for usual Rust
tests in src/dkg.rs and src/dsg.rs
 ### Εxamples (local unit tests with no communication)
- Distributed Key Generation
  `cargo test dkg::dkg2_out_of_2 // 2 parties and t=2`
  `cargo test dkg::dkg2_out_of_3 // 3 parties and t=2`

- Distributed Signatures:
    `cargo test dsg::sign_2_out_of_2`
    `cargo test dsg::sign_2_out_of_3`

- Compute presignature only:
    Run the  `dsg::sign_2_out_of_*` without the last round:

      let mut rng = rand::thread_rng();
      let chain_path = DerivationPath::from_str("m").unwrap();
          let mut parties = dkg(ranks, t)
              .into_iter()
              .take(t as usize)
              .map(|s| State::new(&mut rng, s, &chain_path).unwrap())
              .collect::<Vec<_>>();

          let msg1: Vec<SignMsg1> =
              parties.iter_mut().map(|p| p.generate_msg1()).collect();

          check_serde(&msg1);

          let msg2 = parties.iter_mut().fold(vec![], |mut msg2, party| {
              let batch: Vec<SignMsg1> = msg1
                  .iter()
                  .filter(|msg| msg.from_id != party.keyshare.party_id)
                  .cloned()
                  .collect();
              msg2.extend(party.handle_msg1(&mut rng, batch).unwrap());
              msg2
          });

          check_serde(&msg2);

          let msg3 = parties.iter_mut().fold(vec![], |mut msg3, party| {
              let batch: Vec<SignMsg2> = msg2
                  .iter()
                  .filter(|msg| msg.from_id != party.keyshare.party_id)
                  .cloned()
                  .collect();
              msg3.extend(party.handle_msg2(&mut rng, batch).unwrap());
              msg3
          });

          check_serde(&msg3);

          let pre_signs = parties
              .iter_mut()
              .map(|party| {
                  let batch: Vec<SignMsg3> = msg3
                      .iter()
                      .filter(|msg| msg.from_id != party.keyshare.party_id)
                      .cloned()
                      .collect();

                  party.handle_msg3(batch).unwrap()
              })
              .collect::<Vec<_>>();

          check_serde(&pre_signs);

          let hash = [255; 32];

          let (partials, msg4): (Vec<_>, Vec<_>) = pre_signs
              .into_iter()
              .map(|pre| create_partial_signature(pre, hash))
              .unzip();


## dkls-wasm-ll
WASM bindings for dkls23-ll.

### Build:
Install
[wasm-pack](https://rustwasm.github.io/wasm-pack/):

```curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh```


```shell
wasm-pack build -t web wrapper/wasm-ll
```

### Tests:

To run the test install [deno](https://deno.com):

```curl -fsSL https://deno.land/install.sh | sh```

```shell
deno test -A wrapper/wasm-ll/tests/tests.ts
```

# Articles and links
- DKLs23 https://eprint.iacr.org/2023/765.pdf
- DKG based on Protocol 6.1 https://eprint.iacr.org/2022/374.pdf
- 1 out of 2 Endemic OT Fig.8 https://eprint.iacr.org/2019/706.pdf
- All-but-one OTs from base OTs: Fig.13 and Fig.14 https://eprint.iacr.org/2022/192.pdf
- Generation of *sent_seed_list* and *rec_seed_list* values ​​based on Protocol 2.2 Pairwise Randomization [dkls23_preprint.pdf](docs/dkls23_preprint.pdf)
- SoftSpokenOT protocol https://eprint.iacr.org/2022/192.pdf
- Instantiation of SoftSpokenOT based on Fig.10 https://eprint.iacr.org/2015/546.pdf
- Proactive security definition, Section 2 https://www.iacr.org/archive/eurocrypt2006/40040601/40040601.pdf
