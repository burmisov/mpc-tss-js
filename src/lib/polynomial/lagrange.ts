import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';

import Fn from '../Fn.js';
import { PartyId } from "../keyConfig.js";

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
    numerator = Fn.mul(numerator, xi);
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
      denominator = Fn.mul(denominator, xJ);
    } else {
      denominator = Fn.mul(denominator, Fn.sub(xI, xJ));
    }
  });

  const lJ = Fn.div(numerator, denominator)

  return lJ;
};
