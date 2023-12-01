import { bitLength, gcd, randBytesSync, randBitsSync } from 'bigint-crypto-utils';
import { secp256k1 } from "@noble/curves/secp256k1";
import { randBetween } from "bigint-crypto-utils";
import { bytesToNumberBE } from '@noble/curves/abstract/utils';

import Fn from './Fn.js';
import { AffinePoint } from "./common.types.js";
import { jacobi } from './arith.js';

const SEC_PARAM = 256;
const L = 1 * SEC_PARAM; // = 256
const LPRIME = 5 * SEC_PARAM; // = 1280
const EPSILON = 2 * SEC_PARAM; // = 512
export const L_PLUS_EPSILON = L + EPSILON; // = 768
export const LPRIME_PLUS_EPSILON = LPRIME + EPSILON; // = 1792
export const BITS_INT_MOD_N = 8 * SEC_PARAM; // = 2048
export const STAT_PARAM = 80;

const MAX_ITERATIONS = 256;

export const sampleUnitModN = (modulus: bigint): bigint => {
  const randByteLength = Math.floor((bitLength(modulus) + 7) / 8);
  for (let i = 0; i < MAX_ITERATIONS; i++) {
    const nonceBits = randBytesSync(randByteLength);
    const nonce = BigInt('0x' + nonceBits.toString('hex'));
    const isUnit = (gcd(nonce, modulus) === 1n);
    if (isUnit) {
      return nonce;
    }
  }
  throw new Error('MAX_INT_ITERATIONS_EXCEEDED');
};

export const sampleQNR = (n: bigint): bigint => {
  const randByteLength = Math.floor((BITS_INT_MOD_N) / 8);
  for (let i = 0; i < MAX_ITERATIONS; i++) {
    const rand = randBytesSync(randByteLength);
    const w = bytesToNumberBE(rand);
    if (jacobi(w, n) === -1) {
      return w;
    }
  }
  throw new Error('MAX_INT_ITERATIONS_EXCEEDED');
};

export const sampleModN = (n: bigint): bigint => {
  // TODO: recheck logic
  const out = randBetween(n - 1n);
  return out;
};

export const sampleIntervalLeps = (): bigint => {
  return sampleNeg(L_PLUS_EPSILON);
};

export const sampleIntervalLN = (): bigint => {
  return sampleNeg(L + BITS_INT_MOD_N);
};

export const sampleIntervalLepsN = (): bigint => {
  return sampleNeg(L_PLUS_EPSILON + BITS_INT_MOD_N);
};

export const sampleIntervalLprimeEps = (): bigint => {
  return sampleNeg(LPRIME_PLUS_EPSILON);
}

export const sampleIntervalL = (): bigint => {
  return sampleNeg(L);
};

export const sampleIntervalLprime = (): bigint => {
  return sampleNeg(LPRIME);
}

export const sampleIntervalLEpsRootN = (): bigint => {
  return sampleNeg(L_PLUS_EPSILON + BITS_INT_MOD_N / 2);
};

export const sampleIntervalLN2 = (): bigint => {
  return sampleNeg(L + BITS_INT_MOD_N * 2);
};

export const sampleNeg = (bits: number): bigint => {
  const randomBits = randBitsSync(bits + 1);
  const bigRandomBits = BigInt('0x' + randomBits.toString('hex'));
  const sign = bigRandomBits & 1n;
  const rest = bigRandomBits >> 1n;
  const result = Fn.mod(sign ? -rest : rest);
  return result;
};

export const sampleScalarPointPair = (): [bigint, AffinePoint] => {
  const scalar = randBetween(Fn.N - 1n);
  const point = secp256k1.ProjectivePoint.BASE.multiply(scalar);
  return [scalar, point.toAffine()];
};

export const sampleScalar = (): bigint => randBetween(Fn.N - 1n);
