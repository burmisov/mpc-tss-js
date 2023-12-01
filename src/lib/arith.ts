import { abs, bitLength, gcd } from "bigint-crypto-utils";
import { BITS_INT_MOD_N, LPRIME_PLUS_EPSILON, L_PLUS_EPSILON } from "./sample.js";

export const isValidModN = (n: bigint, x: bigint): boolean => {
  if (typeof x !== "bigint") { return false; }
  if (x >= n) { return false; }
  if (gcd(x, n) !== 1n) { return false; }
  return true;
}

export const isInIntervalLeps = (x: bigint): boolean => {
  return bitLength(x) <= L_PLUS_EPSILON;
}

export const isInIntervalLprimeEps = (x: bigint): boolean => {
  return bitLength(x) <= LPRIME_PLUS_EPSILON;
}

export const isInIntervalLEpsPlus1RootN = (x: bigint): boolean => {
  return bitLength(x) <= 1 + L_PLUS_EPSILON + BITS_INT_MOD_N / 2;
}

export const jacobi = (x: bigint, y: bigint): (-1 | 0 | 1) => {
  if (y === 0n || y % 2n === 0n) {
    throw new Error(`invalid 2nd argument to jacobi: need odd integer but got ${y}`);
  }

  let a = x;
  let b = y;
  let j: -1 | 0 | 1 = 1;

  if (b < 0n) {
    if (a < 0n) {
      j = -1;
    }
    b = -b;
  }

  // TODO: make deterministic exit
  while (true) {
    if (b === 1n) {
      return j;
    }
    if (a === 0n) {
      return 0;
    }
    a = a % b;
    if (a === 0n) {
      return 0;
    }

    const s = trailingZeroBits(abs(a));
    if ((s & 1) !== 0) {
      const bmod8 = b % 8n;
      if (bmod8 === 3n || bmod8 === 5n) {
        j = -j as (-1 | 0 | 1);
      }
    }
    const c = a >> BigInt(s);

    if ((b % 4n === 3n) && (c % 4n === 3n)) {
      j = -j as (-1 | 0 | 1);
    }
    [a, b] = [b, c];
  }
}

const trailingZeroBits = (x: bigint | number): number => {
  const bits = x.toString(2);
  // calculate trailing zeroes in string bits
  let count = 0;
  for (let i = bits.length - 1; i >= 0; i -= 1) {
    if (bits[i] === '0') {
      count++;
    } else {
      break;
    }
  }
  return count;
};
