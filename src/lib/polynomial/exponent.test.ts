import { describe, test } from "node:test";
import assert from 'node:assert/strict';

import { secp256k1 } from "@noble/curves/secp256k1";

import { Polynomial } from "./polynomial.js";
import { Exponent } from "./exponent.js";
import { sampleScalar } from "../sample.js";

describe("Exponent", () => {
  test('evaluate', () => {
    let lhs = secp256k1.ProjectivePoint.ZERO;

    for (let x = 0; x < 5; x++) {
      const N = 10;
      let secret = 0n;
      if (x % 2 === 0) {
        secret = sampleScalar();
      }
      const poly = Polynomial.new(N, secret);
      const polyExp = Exponent.new(poly);

      const randomIndex = sampleScalar();

      const t = poly.evaluate(randomIndex);
      lhs = secp256k1.ProjectivePoint.BASE.multiply(poly.evaluate(randomIndex));
      const rhs1 = secp256k1.ProjectivePoint.fromAffine(polyExp.evaluate(randomIndex));
      const rhs2 = secp256k1.ProjectivePoint.fromAffine(polyExp.evaluateClassic(randomIndex));

      assert(lhs.equals(rhs1), `base eval differs from horner ${x}`);
      assert(lhs.equals(rhs2), `base eval differs from classic ${x}`);
      assert(rhs1.equals(rhs2), `horner differs from classic ${x}`);
    }
  });

  // TODO: more tests
});
