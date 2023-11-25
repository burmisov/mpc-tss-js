import { bitLength, gcd, randBytesSync } from 'bigint-crypto-utils';
import { randBitsSync } from "bigint-crypto-utils";

import Fn from './Fn.js';

const SEC_PARAM = 256;
const L = 1 * SEC_PARAM; // = 256
const EPSILON = 2 * SEC_PARAM; // = 512
export const L_PLUS_EPSILON = L + EPSILON; // = 768
const BITS_INT_MOD_N = 8 * SEC_PARAM; // = 2048

export const sampleUnitModN = (modulus: bigint): bigint => {
  const maxIterations = 256;
  const randByteLength = Math.floor((bitLength(modulus) + 7) / 8);
  for (let i = 0; i < maxIterations; i++) {
    const nonceBits = randBytesSync(randByteLength);
    const nonce = BigInt('0x' + nonceBits.toString('hex'));
    const isUnit = (gcd(nonce, modulus) === 1n);
    if (isUnit) {
      return nonce;
    }
  }
  throw new Error('MAX_INT_ITERATIONS_EXCEEDED');
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

export const sampleIntervalL = (): bigint => {
  return sampleNeg(L);
};

export const sampleNeg = (bits: number): bigint => {
  const randomBits = randBitsSync(bits + 1);
  const bigRandomBits = BigInt('0x' + randomBits.toString('hex'));
  const sign = bigRandomBits & 1n;
  const rest = bigRandomBits >> 1n;
  const result = Fn.mod(sign ? -rest : rest);
  return result;
};
