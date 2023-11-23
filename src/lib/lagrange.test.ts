import { describe, it } from "node:test";
import assert from 'node:assert/strict';

import { secp256k1 } from "@noble/curves/secp256k1";

import { lagrange } from "./lagrange.js";

const Fp = secp256k1.CURVE.Fp;

describe("Lagrange", async () => {
  const fpSum = (args: bigint[]): bigint => {
    return args.reduce((acc, x) => Fp.add(acc, x), Fp.ZERO);
  }

  it("correctly computes", async () => {
    const tenIds = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'];
    const nineIds = tenIds.slice(0, 9);

    const coefsEven = lagrange(tenIds);
    const coefsOdd = lagrange(nineIds);

    const sumEven = fpSum(Object.values(coefsEven));
    const sumOdd = fpSum(Object.values(coefsOdd));

    assert.equal(sumEven, Fp.ONE, 'Sum of coefficients is not 1');
    assert.equal(sumOdd, Fp.ONE, 'Sum of coefficients is not 1');
  });
});
