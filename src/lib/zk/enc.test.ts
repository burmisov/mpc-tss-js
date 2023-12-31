import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  ZkEncPrivate, ZkEncPublic,
  zkEncCreateProof, zkEncVerifyProof,
} from "./enc.js";
import { sampleIntervalL } from "../sample.js";
import { PaillierSecretKey } from "../paillier.js";
import { validatePaillierPrime } from '../paillierKeygen.js';
import { Hasher } from "../Hasher.js";


describe("zk/enc", () => {
  it("create proof and verify", async () => {
    const k = sampleIntervalL();

    const p = 179592502110335963336347735108907147317760904272746519157588428198851642173043932077383231024080457777437444199308940940528740158020956955835017958704625931695110457545843284994471316520797998498062474296013358438785968440081020607611888287234488233606613994066898948321434201732737366068220153564935475802567n;
    const q = 144651337722999591357894368476987413731327694772730408677878934803626218325763401733049627551150267745019646164141178748986827450041894571742897062718616997949877925740444144291875968298065299373438319317040746398994377200405476019627025944607850551945311780131978961657839712750089596117856255513589953855963n;
    await validatePaillierPrime(p);
    await validatePaillierPrime(q);
    const paillierSecretKey = PaillierSecretKey.fromPrimes(p, q);
    const paillierPublicKey = paillierSecretKey.publicKey;

    const { pedersen } = paillierSecretKey.generatePedersen();

    const { ciphertext: K, nonce: rho } = paillierPublicKey.encrypt(k);

    const zkEncPublic: ZkEncPublic = {
      K, prover: paillierPublicKey, aux: pedersen,
    };
    const zkEncPrivate: ZkEncPrivate = {
      k, rho,
    };

    const hasher = Hasher.create().update('test');

    const proof = zkEncCreateProof(zkEncPublic, zkEncPrivate, hasher.clone());

    const verified = zkEncVerifyProof(proof, zkEncPublic, hasher.clone());

    assert.equal(verified, true, 'Proof verification failed');
  });
});
