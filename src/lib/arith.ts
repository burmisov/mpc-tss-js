import { bitLength, gcd } from "bigint-crypto-utils";
import { LPRIME_PLUS_EPSILON, L_PLUS_EPSILON } from "./sample.js";

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
