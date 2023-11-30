# mpc-tss-js

**WARNING: Work in progress!**

An attempt to implement a multi-party computation (MPC) threshold signature scheme (TSS) in Javascript/Typescript for use on Node.js, browsers, react-native apps and other modern JS platforms. This strives to be secure and auditable, based on state of the art research and proven implementations, MIT-licensed.

The approach is described in the original paper by Canetti et al.,
"UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts"
https://eprint.iacr.org/2021/060

## Current status

Updated Nov 30, 2023

Milestone 1 complete -- the library is able to perform a "2 out of 3" or
"3 out of 3" parties ECDSA signature (and probably other party numbers, too),
the signature is validated both internally and with Ethereum tools. The 3 parties
key configuration used is pre-created using the original
[multi-party-sig](https://github.com/taurusgroup/multi-party-sig) library.
Milestone 2 is going to be the key generation ceremony implementation, but before that
it needs some care with state/parameters validation and cleanup.

## How to use

Until Milestone 2 I see no point exporting any API or interfaces so the best you
can do now is to run the tests:

**Use Node.js 21+**

```
git clone git@github.com:burmisov/mpc-tss-js.git
cd mpc-tss-js
npm install
npm test
```

The signature test uses a pre-created 3-party key configuration and handles (more
like emulates) signatories communication throught the 5 rounds of creating a signature.

## Current goals

1. Make a full useable cycle with creating a multi-party key setup (key generation process)
2. Everything else is secondary at this point; this includes docs, comments, links, performance optimization, proper packaging, even some mid-to-low grade security aspects, etc.

## Known issues and limitations

1. Doesn't really perform a full-cycle useful service as of current status; this is about to change
2. Some operations that could be constant time are not currently constant time
3. No proper per-round validation of completeness of input parameters
4. Signing session and state passing between rounds is a bit messy
5. There's no consistent serialization and deserialization routints for all the necessary objects
6. Known factorization is not reused to speed some things up; this can be added later
7. [ likely there's more ]

## TODOs:

### Features

- [ ] MILESTONE 2: Implement a key generation ceremony; generate valid party setups and create a valid signature
- [ ] ZK Proofs -- sch
- [ ] ZK Proofs -- fac
- [ ] ZK Proofs -- mod
- [ ] ZK Proofs -- prm
- [ ] Polynimials
- [ ] Keygen round 1
- [ ] Keygen round 2
- [ ] Keygen round 3
- [ ] Keygen round 4
- [ ] Keygen round 5
- [ ] End-to-end test with keygen and signing with fresh keys

### Other

- [ ] Hashing with domains
- [ ] BIP32 signing
- [ ] Refactor and cleanup
- [ ] Devise a predictable Error model
- [ ] ElGamal
- [ ] Oblivious Transfer
- [ ] Create a proper readme
- [ ] Add a workflow to test and publish
- [ ] Configure my system for signed commits
- [ ] MILESTONE 3+: Review, add Schnorr and Ed25519 signatures to the scope, implement key refresh ceremony, etc.

### Docs

- [ ] Explicitly list dependencies
- [ ] Link to my instrumented multi-party-sig fork
- [ ] Lay out motivation and prior art
- [ ] Lay out the goals and the plan

##### Done:

- [x] MILESTONE 1: Create a valid signature via "online" ceremony given pre-created party setups
- [x] Paillier encryption scheme internal library (minimal)
- [x] Keyconfig (party setup) data
- [x] Pedersen
- [x] Lagrange
- [x] ZK Proofs -- zk/enc
- [x] Signing Round 1 !
- [x] ZK Proofs -- zk/logstar
- [x] ZK Proofs -- zk/affg
- [x] ZK Proofs -- zk/affp
- [x] MTA
- [x] Signing Round 2
- [x] Signing Round 3
- [x] Signing Round 4
- [x] Signing Round 5
- [x] Covert to Ethereum signature and verify with external tool
- [x] Fix session hashing
- [x] Blake3-based hasher class
- [x] Signing round data and implementations
- [x] ECDSA with secp256k1 utils (use/wrap @noble/curves -- did use it)

## Intellectual Property

Copyright 2023 Sergey Burmisov (burmisov.com)

```
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this work except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

Major components of this library are derived from the original Go-language library:

https://github.com/taurusgroup/multi-party-sig

While no original source files are used as-is, many JS/TS files closely rewrite the
original Go files. Other parts adhere to similar semantics as the original library, and
other sections are original due to JS/TS idiosyncrasies or simply at the author's
discretion.

Original Go multi-party-sig copyright notice:  
copyright (c) Adrian Hamelink and Taurus SA, 2021, and under Apache 2.0 license.
