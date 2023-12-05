import { describe, test } from "node:test";
import assert from 'node:assert/strict';

import { secp256k1 } from "@noble/curves/secp256k1";

import { Polynomial } from "./polynomial.js";
import { Exponent } from "./exponent.js";
import { sampleScalar } from "../sample.js";
import Fn from "../Fn.js";

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
      const polyExp = Exponent.fromPoly(poly);

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

  test('sum', () => {
    const N = 20;
    const Deg = 10;

    const randomIndex = sampleScalar();

    let evaluationScalar = 0n;
    let evaluationPartial = secp256k1.ProjectivePoint.ZERO;
    const polys: Polynomial[] = [];
    const polysExp: Exponent[] = [];
    for (let i = 0; i < N; i++) {
      const sec = sampleScalar();
      polys[i] = Polynomial.new(Deg, sec);
      polysExp[i] = Exponent.fromPoly(polys[i]);

      evaluationScalar = Fn.add(evaluationScalar, polys[i].evaluate(randomIndex));
      evaluationPartial = evaluationPartial.add(
        secp256k1.ProjectivePoint.fromAffine(polysExp[i].evaluate(randomIndex)),
      );
    }

    const summedExp = Exponent.sum(polysExp);
    const evaluationSum = summedExp.evaluate(randomIndex);

    const evaluationFromScalar =
      secp256k1.ProjectivePoint.BASE.multiply(evaluationScalar);

    const evaluationSumProj = secp256k1.ProjectivePoint.fromAffine(evaluationSum);
    assert(evaluationSumProj.equals(evaluationFromScalar));
    assert(evaluationSumProj.equals(evaluationPartial));
  });
});
