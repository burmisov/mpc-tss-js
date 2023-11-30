import { describe, test } from "node:test";
import assert from 'node:assert/strict';

import { sampleScalar } from "../sample.js";
import { randBetween } from "bigint-crypto-utils";

import { Polynomial } from "./polynomial.js";

describe("Polynomial", () => {
  test('constant', () => {
    const deg = 10;
    const secret = sampleScalar();
    const poly = Polynomial.new(deg, secret);
    assert.equal(poly.constant(), secret);
  });

  test('evaluate', () => {
    const poly = Polynomial.fromCoefficients([1n, 0n, 1n]);
    for (let i = 0; i < 100; i++) {
      const rand = randBetween(2n ** 32n);
      const computedResult = poly.evaluate(rand);
      const expectedResult = rand * rand + 1n;;
      assert.equal(computedResult, expectedResult);
    }
  });
});
