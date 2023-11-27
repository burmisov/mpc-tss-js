import { secp256k1 } from "@noble/curves/secp256k1";
import { ProjectivePoint } from "./common.types.js";
import { bitLength } from "bigint-crypto-utils";
import { bytesToNumberBE } from "@noble/curves/abstract/utils";

// Identity point? TODO: check if this is the right way to do it
export const isIdentity = (point: ProjectivePoint) => {
  return (point.px === 0n && point.py === 0n) || point.pz === 0n;
};

export const scalarFromHash = (hashIn: Uint8Array): bigint => {
  const order = secp256k1.CURVE.n;
  const orderBits = bitLength(order);
  const orderBytes = Math.floor((orderBits + 7) / 8);
  let hash: Uint8Array;
  if (hashIn.length > orderBytes) {
    hash = hashIn.slice(0, orderBytes);
  } else {
    hash = hashIn;
  }

  let scalar = bytesToNumberBE(hash);
  const excess = hash.length * 8 - orderBits;
  if (excess > 0) {
    scalar = scalar >> BigInt(excess);
  }

  return scalar;
};
