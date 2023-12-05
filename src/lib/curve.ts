import { secp256k1 } from "@noble/curves/secp256k1";
import { AffinePoint, AffinePointSerialized, ProjectivePoint } from "./common.types.js";
import { bitLength } from "bigint-crypto-utils";
import { bytesToNumberBE, numberToBytesBE } from "@noble/curves/abstract/utils";
import Fn from "./Fn.js";

// Identity point? TODO: check if this is the right way to do it
export const isIdentity = (point: ProjectivePoint) => {
  return (point.px === 0n && point.py === 0n) || point.pz === 0n;
};

export const pointToJSON = (point: AffinePoint): AffinePointSerialized => {
  return {
    xHex: point.x.toString(16),
    yHex: point.y.toString(16),
  };
};

export const pointFromJSON = (point: AffinePointSerialized): AffinePoint => {
  return {
    x: BigInt(`0x${point.xHex}`),
    y: BigInt(`0x${point.yHex}`),
  };
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

export const verifySignature = (
  sigR: AffinePoint,
  sigS: bigint,
  X: AffinePoint,
  hash: Uint8Array,
): boolean => {
  const r = sigR.x;
  if (r === 0n || sigS === 0n) { return false; }

  const m = scalarFromHash(hash);
  const sInv = Fn.inv(sigS);
  const mG = secp256k1.ProjectivePoint.BASE.multiply(m);
  const rX = secp256k1.ProjectivePoint.fromAffine(X).multiply(r);
  const R2 = mG.add(rX).multiply(sInv);

  return secp256k1.ProjectivePoint.fromAffine(sigR).equals(R2);
};

export const pointToEcdsaBytes = (point: AffinePoint): Uint8Array => {
  const ppoint = secp256k1.ProjectivePoint.fromAffine(point);
  const xBytes = numberToBytesBE(point.x, 32);
  const yByte = ppoint.hasEvenY() ? 0x02 : 0x03;
  const bytes = new Uint8Array(33);
  bytes[0] = yByte;
  bytes.set(xBytes, 1);
  return bytes;
};
