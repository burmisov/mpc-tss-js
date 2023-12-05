import { describe, test } from "node:test";
import assert from "node:assert/strict";

import { modMultiply, modPow } from "bigint-crypto-utils";

import { sampleQNR } from "../sample.js";
import { PaillierSecretKey } from "../paillier.js";
import { validatePaillierPrime } from '../paillierKeygen.js';
import { Hasher } from "../Hasher.js";
import {
  ZkModPrivate, ZkModPublic,
  zkModChallenge, zkModCreateProof, zkModFourthRootExponent,
  zkModIsProofValid, zkModMakeQuadraticResidue, zkModVerifyProof,
} from './mod.js';

describe("zk/mod", async () => {
  const p = 167495246782569910107862669897619243075835098207853220101403982609959943903743345646375788362909715211900141652671436007095125366426921092792005772260273820630537327116191279465491203987638225198595642843240698088777581339844121640128731583440776342448939839731522446469995390448902946229002446098530004835239n;
  const q = 178784929586423449637890491161861655617854412540709400421874212815293580828404739498291345696103341491924297140261396221041987821086550770172144419152711267591283272834659746554330603868249176073673884285246036132552905332762099384955889000396765335249879642433930458968871576233738650973235318810378637560383n;
  await validatePaillierPrime(p);
  await validatePaillierPrime(q);
  const paillierSecretKey = PaillierSecretKey.fromPrimes(p, q);

  test('setFourthRoot', async () => {
    const p = 311n;
    const q = 331n;
    const pHalf = (p - 1n) / 2n;
    const qHalf = (q - 1n) / 2n;
    const n = p * q;
    const phi = (p - 1n) * (q - 1n);
    let y = 502n;
    const w = sampleQNR(n);

    const nCRT = p * q; //

    const { a, b, out: x } = zkModMakeQuadraticResidue(y, w, pHalf, qHalf, n, p, q);

    const e = zkModFourthRootExponent(phi);
    const root = modPow(x, e, nCRT);
    if (b) {
      y = modMultiply([y, w], n);
    }
    if (a) {
      y = modMultiply([y, -1n], n);
    }

    assert.notEqual(root, 1n, "root cannot be 1");
    const root4 = modPow(root, 4n, n);
    assert.equal(root4, y, "root^4 should be equal to y");
  });

  test('hashfix', async () => {
    const N = paillierSecretKey.publicKey.n;
    const w = sampleQNR(N);
    const hasher = Hasher.create().update('test');
    const es = zkModChallenge(hasher, N, w);

    let allEqual = true;
    for (const e of es) {
      if (e !== es[0]) {
        allEqual = false;
      }
    }

    assert.equal(allEqual, false, "all challenges should be different");
  });

  test('mod', async () => {
    const hasher = Hasher.create().update('test');

    const pub: ZkModPublic = { N: paillierSecretKey.publicKey.n };
    const priv: ZkModPrivate = { P: p, Q: q, Phi: paillierSecretKey.phi };
    const proof = zkModCreateProof(priv, pub, hasher.clone());

    const valid = zkModIsProofValid(proof, pub);
    assert.equal(valid, true, "proof should be valid");

    const verified = await zkModVerifyProof(proof, pub, hasher.clone());
    assert.equal(verified, true, "proof should be verified");

    proof.W = 0n;
    for (const r of proof.Responses) {
      r.X = 0n;
    }
    const verified2 = await zkModVerifyProof(proof, pub, hasher.clone());
    assert.equal(verified2, false, "corrupted proof should fail");
  });
});
