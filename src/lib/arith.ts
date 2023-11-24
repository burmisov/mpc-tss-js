import { gcd } from "bigint-crypto-utils";

export const isValidModN = (n: bigint, x: bigint): boolean => {
  if (typeof x !== "bigint") { return false; }
  if (x >= n) { return false; }
  if (gcd(x, n) !== 1n) { return false; }
  return true;
}
