import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

import Fn from "../Fn.js";
import { isValidModN } from "../arith.js";
import {
  PaillierPublicKey, paillierAdd, paillierEncryptWithNonce,
  paillierMultiply, validateCiphertext
} from "../paillier.js";
import { PedersenParameters, pedersenCommit, pedersenVerify } from "../pedersen.js";
import { bitLength, modMultiply, modPow } from "bigint-crypto-utils";
import {
  sampleUnitModN, sampleIntervalLeps, sampleIntervalLN,
  sampleIntervalLepsN, L_PLUS_EPSILON,
} from "../sample.js";
import { Hasher } from "../Hasher.js";

export type ZkEncPublicKey = {
  K: bigint, // Paillier ciphertext
  prover: PaillierPublicKey,
  aux: PedersenParameters,
};

export type ZkEncPrivateKey = {
  k: bigint,
  rho: bigint,
};

export type ZkEncCommitment = {
  S: bigint,
  A: bigint, // Paillier ciphertext
  C: bigint,
};

export type ZkEncProof = {
  commitment: ZkEncCommitment,
  Z1: bigint,
  Z2: bigint,
  Z3: bigint,
};

export type ZkEncProofSerialized = {
  commitment: {
    Shex: string,
    Ahex: string,
    Chex: string,
  },
  Z1signedHex: string,
  Z2hex: string,
  Z3signedHex: string,
};

export const zkEncSerializeProof = (proof: ZkEncProof): ZkEncProofSerialized => {
  return {
    commitment: {
      Shex: proof.commitment.S.toString(16),
      Ahex: proof.commitment.A.toString(16),
      Chex: proof.commitment.C.toString(16),
    },
    Z1signedHex: proof.Z1.toString(16),
    Z2hex: proof.Z2.toString(16),
    Z3signedHex: proof.Z3.toString(16),
  };
}

export const zkEncCreateProof = (
  publicKey: ZkEncPublicKey,
  privateKey: ZkEncPrivateKey,
): ZkEncProof => {
  const alpha = sampleIntervalLeps();
  const r = sampleUnitModN(publicKey.prover.n);
  const mu = sampleIntervalLN();
  const gamma = sampleIntervalLepsN();

  const A = paillierEncryptWithNonce(publicKey.prover, alpha, r);

  const commitment: ZkEncCommitment = {
    S: pedersenCommit(publicKey.aux, privateKey.k, mu),
    A,
    C: pedersenCommit(publicKey.aux, alpha, gamma),
  };

  const e = challenge(publicKey, commitment);

  const Z1 = privateKey.k * e + alpha;
  const Z2 = modMultiply(
    [
      modPow(privateKey.rho, e, publicKey.prover.n),
      r,
    ],
    publicKey.prover.n
  )
  const Z3 = e * mu + gamma;

  return {
    commitment,
    Z1, Z2, Z3,
  };
};

export const zkEncVerifyProof = (
  proof: ZkEncProof,
  publicKey: ZkEncPublicKey,
): boolean => {
  if (!zkEncIsPublicKeyValid(proof, publicKey)) { return false; }
  if (bitLength(proof.Z1) > L_PLUS_EPSILON) { return false; }

  const e = challenge(publicKey, proof.commitment);
  if (!pedersenVerify(
    publicKey.aux, proof.Z1, proof.Z3, e, proof.commitment.C, proof.commitment.S,
  )) {
    return false;
  }

  const lhs = paillierEncryptWithNonce(publicKey.prover, proof.Z1, proof.Z2);
  const rhs = paillierAdd(
    publicKey.prover,
    paillierMultiply(publicKey.prover, publicKey.K, e),
    proof.commitment.A
  );

  return lhs === rhs;
}

export const zkEncIsPublicKeyValid = (
  proof: ZkEncProof,
  publicKey: ZkEncPublicKey,
): boolean => {
  if (!proof) { return false; }
  if (!validateCiphertext(publicKey.prover, proof.commitment.A)) { return false; }
  if (!isValidModN(publicKey.prover.n, proof.Z2)) { return false; }
  return true;
}

const bigintToBytes = (x: bigint): Uint8Array => {
  const hex = x.toString(16);
  if (hex.length % 2 === 1) {
    return hexToBytes('0' + hex);
  }
  return hexToBytes(hex);
}

const challenge = (
  publicKey: ZkEncPublicKey,
  commitment: ZkEncCommitment,
): bigint => {
  const bigHash = new Hasher().updateMulti([
    publicKey.aux,
    publicKey.prover,
    publicKey.K,
    commitment.S,
    commitment.A,
    commitment.C,
  ]).digestBigint();

  const challenge = Fn.sub(bigHash, 2n ** 255n); // TODO

  return challenge
}
