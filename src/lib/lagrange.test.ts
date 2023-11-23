import { describe, it } from "node:test";
import assert from 'node:assert/strict';

import Fn from "./Fn.js";

import { lagrange } from "./lagrange.js";

describe("Lagrange", async () => {
  const fpSum = (args: bigint[]): bigint => {
    return args.reduce((acc, x) => Fn.add(acc, x), 0n);
  }

  it("correctly computes", async () => {
    const tenIds = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'];
    const nineIds = tenIds.slice(0, 9);

    const coefsEven = lagrange(tenIds);
    const coefsOdd = lagrange(nineIds);

    const sumEven = fpSum(Object.values(coefsEven));
    const sumOdd = fpSum(Object.values(coefsOdd));

    assert.equal(sumEven, 1n, 'Sum of coefficients is not 1');
    assert.equal(sumOdd, 1n, 'Sum of coefficients is not 1');
  });
});
