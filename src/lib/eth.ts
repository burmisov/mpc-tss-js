import { numberToBytesBE } from "@noble/curves/abstract/utils";
import { bytesToHex } from "@noble/hashes/utils";
import { keccak_256 } from "@noble/hashes/sha3";

import Fn from "./Fn.js";
import { AffinePoint } from "./common.types.js";
import { pointToEcdsaBytes } from "./curve.js";

export const sigEthereum = (
  sigRin: AffinePoint,
  sigSin: bigint,
): Uint8Array => {
  let sigR = sigRin.x;
  let sigS = sigSin;

  const isOverHalfOrder = Fn.isOverHalfOrder(sigS);

  if (isOverHalfOrder) {
    sigS = Fn.mod(-sigS);
  }

  const sigRBytes = pointToEcdsaBytes(sigRin);
  const sigSBytes = numberToBytesBE(sigS, 32);

  let rs = new Uint8Array(65);
  rs.set(sigRBytes, 0);
  rs.set(sigSBytes, 33);

  if (isOverHalfOrder) {
    const v = rs[0] - 2;
    rs.set(rs.slice(1), 0);
    rs[64] = v ^ 1;
  } else {
    const v = rs[0] - 2;
    rs.set(rs.slice(1), 0);
    rs[64] = v;
  }

  // TODO: check r
  return rs;
};

export const ethAddress = (pub: AffinePoint): string => {
  const xBytes = numberToBytesBE(pub.x, 32);
  const yBytes = numberToBytesBE(pub.y, 32);
  const pubKeyBytes = new Uint8Array(64);
  pubKeyBytes.set(xBytes, 0);
  pubKeyBytes.set(yBytes, 32);
  const hash = keccak_256(pubKeyBytes);
  const addressBytes = hash.slice(-20);
  return '0x' + bytesToHex(addressBytes);
};
