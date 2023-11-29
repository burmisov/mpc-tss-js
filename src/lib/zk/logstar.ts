import { secp256k1 } from "@noble/curves/secp256k1";

import { isInIntervalLeps, isValidModN } from "../arith.js";
import { AffinePoint } from "../common.types.js";
import { PaillierPublicKey, paillierAdd, paillierEncryptWithNonce, paillierMultiply, validateCiphertext } from "../paillier.js";
import { PedersenParameters, pedersenCommit, pedersenVerify } from "../pedersen.js";
import {
  sampleIntervalLN, sampleIntervalLeps, sampleIntervalLepsN,
  sampleUnitModN,
} from "../sample.js";
import Fn from "../Fn.js";
import { Hasher } from "../Hasher.js";
import { modMultiply, modPow } from "bigint-crypto-utils";
import { isIdentity } from "../curve.js";

export type ZkLogstarPublic = {
  C: bigint; // ciphertext
  X: AffinePoint;
  G?: AffinePoint;
  prover: PaillierPublicKey;
  aux: PedersenParameters;
};

export type ZkLogstarPrivate = {
  X: bigint;
  Rho: bigint;
};

export type ZkLogstarCommitment = {
  S: bigint;
  A: bigint; // ciphertext
  Y: AffinePoint;
  D: bigint;
};

export type ZkLogstarProof = {
  commitment: ZkLogstarCommitment;
  Z1: bigint;
  Z2: bigint;
  Z3: bigint;
};

export const zkLogstarIsProofValid = (
  proof: ZkLogstarProof,
  pub: ZkLogstarPublic,
): boolean => {
  if (!proof) { return false; }
  if (!validateCiphertext(pub.prover, proof.commitment.A)) { return false; }
  const point = secp256k1.ProjectivePoint.fromAffine(proof.commitment.Y);
  if (isIdentity(point)) { return false; }
  if (!isValidModN(pub.prover.n, proof.Z2)) { return false; }
  return true;
}

export const zkLogstarCreateProof = (
  pubIn: ZkLogstarPublic,
  priv: ZkLogstarPrivate,
  hasher: Hasher,
): ZkLogstarProof => {
  // TODO optimize
  const pub = {
    ...pubIn,
    G: pubIn.G ?? secp256k1.ProjectivePoint.BASE.toAffine(),
  };

  const alpha = sampleIntervalLeps();
  const r = sampleUnitModN(pub.prover.n);
  const mu = sampleIntervalLN();
  const gamma = sampleIntervalLepsN();

  const pointG = secp256k1.ProjectivePoint.fromAffine(pub.G);
  const commitment: ZkLogstarCommitment = {
    A: paillierEncryptWithNonce(pub.prover, alpha, r),
    Y: pointG.multiply(Fn.mod(alpha)).toAffine(),
    S: pedersenCommit(pub.aux, priv.X, mu),
    D: pedersenCommit(pub.aux, alpha, gamma),
  };

  const e = challenge(pub, commitment, hasher);

  const Z1 = priv.X * e + alpha;
  const Z2 = modMultiply(
    [
      modPow(priv.Rho, e, pub.prover.n),
      r,
    ],
    pub.prover.n,
  );
  const Z3 = e * mu + gamma;

  const proof: ZkLogstarProof = {
    commitment,
    Z1,
    Z2,
    Z3,
  };

  return proof;
}

export const zkLogstarVerifyProof = (
  proof: ZkLogstarProof,
  pubIn: ZkLogstarPublic,
  hasher: Hasher,
): boolean => {
  const pub = {
    ...pubIn,
    G: pubIn.G ?? secp256k1.ProjectivePoint.BASE.toAffine(),
  };

  if (!zkLogstarIsProofValid(proof, pubIn)) { return false; }

  if (!isInIntervalLeps(proof.Z1)) { return false; }

  const e = challenge(pub, proof.commitment, hasher);

  if (!pedersenVerify(
    pub.aux, proof.Z1, proof.Z3, e, proof.commitment.D, proof.commitment.S,
  )) { return false; }

  const lhs = paillierEncryptWithNonce(pub.prover, proof.Z1, proof.Z2);
  const rhs = paillierAdd(
    pub.prover,
    paillierMultiply(pub.prover, pub.C, e),
    proof.commitment.A,
  );

  return lhs === rhs;
};

const challenge = (
  pub: ZkLogstarPublic,
  commitment: ZkLogstarCommitment,
  hasher: Hasher,
): bigint => {
  const bigHash = hasher.updateMulti([
    pub.aux,
    pub.prover,
    pub.C,
    pub.X,
    pub.G ?? 0n,
    commitment.S,
    commitment.A,
    commitment.Y,
    commitment.D,
  ]).digestBigint();

  const challenge = Fn.sub(bigHash, 2n ** 255n); // TODO

  return challenge
}
