import { secp256k1 } from "@noble/curves/secp256k1";
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';

import { PartyId } from "./keyConfig.js";

const Fp = secp256k1.CURVE.Fp;

export const lagrange = (
  interpolationDomain: PartyId[],
): Record<PartyId, bigint> => {
  return lagrangeFor(interpolationDomain, interpolationDomain);
}

const lagrangeFor = (
  interpolationDomain: PartyId[],
  subset: PartyId[]
): Record<PartyId, bigint> => {
  const { scalars, numerator } = getScalarsAndNumerator(interpolationDomain);
  const coefficients: Record<PartyId, bigint> = {};
  for (const j of subset) {
    coefficients[j] = lagrangeInternal(scalars, numerator, j);
  }
  return coefficients;
};

const getScalarsAndNumerator = (
  interpolationDomain: PartyId[],
): {
  scalars: Record<PartyId, bigint>,
  numerator: bigint,
} => {
  const scalars: Record<PartyId, bigint> = {};
  let numerator = 1n;
  for (const id of interpolationDomain) {
    const idBytes = utf8ToBytes(id);
    const xi = BigInt('0x' + bytesToHex(idBytes));
    scalars[id] = xi;
    numerator = Fp.mul(numerator, xi);
  }
  return { scalars, numerator };
}

const lagrangeInternal = (
  interpolationDomain: Record<PartyId, bigint>,
  numerator: bigint,
  j: PartyId,
): bigint => {
  const xJ = interpolationDomain[j];

  let denominator = 1n;
  Object.entries(interpolationDomain).forEach(([i, xI]) => {
    if (i === j) {
      denominator = Fp.mul(denominator, xJ);
    } else {
      denominator = Fp.mul(denominator, Fp.add(Fp.neg(xJ), xI));
    }
  });

  const lJ = Fp.mul(Fp.inv(denominator), numerator);

  return lJ;
};
