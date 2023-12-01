import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { zkSchCreateRandomness, zkSchProve, zkSchVerifyResponse } from "./zksch.js";
import { sampleScalar, sampleScalarPointPair } from "../sample.js";
import { Hasher } from "../Hasher.js";
import { secp256k1 } from "@noble/curves/secp256k1";

describe("zk/sch", () => {
  const hasher = Hasher.create().update('test');

  test('pass', () => {
    const a = zkSchCreateRandomness();
    const [x, X] = sampleScalarPointPair();

    const proof = zkSchProve(a, hasher.clone(), X, x);
    assert(
      zkSchVerifyResponse(proof, hasher.clone(), X, a.commitment),
      'failed to verify response',
    );
    assert(
      zkSchVerifyResponse(proof, hasher.clone(), X, a.commitment),
    );
  });

  test('fail', () => {
    const a = zkSchCreateRandomness();
    const [x, X] = [sampleScalar(), secp256k1.ProjectivePoint.ZERO.toAffine()];
    const proof = zkSchProve(a, hasher.clone(), X, x);
    assert.equal(
      zkSchVerifyResponse(proof, hasher.clone(), X, a.commitment),
      false,
      'proof should not accept identity point',
    );
  });
});
