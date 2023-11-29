# mpc-tss-js

**WARNING: Work in progress!**

An attempt to implement a multi-party computation (MPC) threshold signature scheme (TSS) in Javascript/Typescript for use on Node.js, browsers, react-native apps and other modern JS platforms. This strives to be secure and auditable, based on state of the art research and proven implementations, MIT-licensed.

The approach is described in the original paper by Canetti et al.,
"UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts"
https://eprint.iacr.org/2021/060

Current status: some playing around with architecture and sources of inspiration.

## TODO

### Features

- [ ] MILESTONE 1: Create a valid signature via "offline" ceremony given pre-created party setups
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
- [ ] Hashing with domains
- [ ] BIP32 signing
- [ ] Refactor and cleanup
- [ ] ZK Proofs -- others
- [ ] Blake3-based hasher class?
- [ ] Devise a predictable Error model
- [ ] ECDSA with secp256k1 utils (use/wrap @noble/curves ?)
- [ ] ElGamal
- [ ] Oblivious Transfer
- [ ] Signing round data and implementations
- [ ] MILESTONE 2: Implement a key generation ceremony; generate valid party setups and create a valid signature
- [ ] MILESTONE 3+: Review, add Schnorr and Ed25519 signatures to the scope, implement key refresh ceremony, etc.

### General

- [ ] Create a proper readme
- [ ] Add a workflow to test and publish
- [ ] Configure my system for signed commits

### Doc

- [ ] Explicitly list dependencies
- [ ] Link to my instrumented multi-party-sig fork
- [ ] Lay out motication and prior art
- [ ] Lay out the goals and the plan

## Plans and Acknowledgements

My original intention was to do a close-to-code rewrite of ECSDA-related parts of
"Multi-Party-Sig" from Taurus Group, https://github.com/taurusgroup/multi-party-sig
Copyright (c) Adrian Hamelink and Taurus SA, 2021, and under Apache 2.0 license.

That library is written in the Go language. After doing some initial tries, I realized that it is not practical to do a close-to-code rewrite in JS due to multiple idiomatic reasons. So I still intend to use the library heavily as a proof-of-concept implementation that I can rely upon, but the code will probably differ quite a lot in the end. I'll see how can I structure the code to balance paying tribute to that library and also making a readable standalone Typescript library, and eager to provide all the proper attribution.
