# mpc-tss-js

**WARNING: Work in progress!**

An attempt to implement a multi-party computation (MPC) threshold signature scheme (TSS) in Javascript/Typescript for use on Node.js, browsers, react-native apps and other modern JS platforms. This strives to be secure and auditable, based on state of the art research and proven implementations, MIT-licensed.

The approach is described in the original paper by Canetti et al.,
"UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts"
https://eprint.iacr.org/2021/060

Current status: some playing around with architecture and sources of inspiration.

TODO (to be expanded):
* [ ] Create a proper readme
* [ ] Lay out motication and prior art
* [ ] Lay out the goals and the plan
* [ ] Do it :)

## Plans and Acknowledgements

My original intention was to do a close-to-code rewrite of ECSDA-related parts of
"Multi-Party-Sig" from Taurus Group, https://github.com/taurusgroup/multi-party-sig
Copyright (c) Adrian Hamelink and Taurus SA, 2021, and under Apache 2.0 license.

That library is written in the Go language. After doing some initial tries, I realized that it is not practical to do a close-to-code rewrite in JS due to multiple idiomatic reasons. So I still intend to use the library heavily as a proof-of-concept implementation that I can rely upon, but the code will probably differ quite a lot in the end. I'll see how can I structure the code to balance paying tribute to that library and also making a readable standalone Typescript library, and eager to provide all the proper attribution.
