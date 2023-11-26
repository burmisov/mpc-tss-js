import { secp256k1 } from "@noble/curves/secp256k1";
import { modMultiply, modPow } from "bigint-crypto-utils";

import { isInIntervalLeps, isInIntervalLprimeEps, isValidModN } from "../arith.js";
import { AffinePoint } from "../common.types.js";
import {
  PaillierPublicKey,
  paillierAdd, paillierEncryptWithNonce, paillierMultiply,
  validateCiphertext
} from "../paillier.js";
import { PedersenParameters, pedersenCommit, pedersenVerify } from "../pedersen.js";
import {
  sampleIntervalLN, sampleIntervalLeps, sampleIntervalLepsN,
  sampleIntervalLprimeEps, sampleUnitModN,
} from "../sample.js";
import Fn from "../Fn.js";
import { Hasher } from "../Hasher.js";


export type ZkAffgPublic = {
  Kv: bigint; // ciphertext
  Dv: bigint; // ciphertext
  Fp: bigint; // ciphertext
  Xp: AffinePoint;
  prover: PaillierPublicKey;
  verifier: PaillierPublicKey;
  aux: PedersenParameters;
};

export type ZkAffgPrivate = {
  X: bigint;
  Y: bigint;
  S: bigint;
  R: bigint;
};

export type ZkAffgCommitment = {
  A: bigint; // ciphertext
  Bx: AffinePoint;
  By: bigint; // ciphertext
  E: bigint;
  S: bigint;
  F: bigint;
  T: bigint;
};

export type ZkAffgProof = {
  commitment: ZkAffgCommitment;
  Z1: bigint;
  Z2: bigint;
  Z3: bigint;
  Z4: bigint;
  W: bigint;
  Wy: bigint;
};

export const zkAffgIsProofValid = (
  proof: ZkAffgProof,
  pub: ZkAffgPublic,
): boolean => {
  if (!proof) { return false; }
  if (!validateCiphertext(pub.verifier, proof.commitment.A)) { return false; }
  if (!validateCiphertext(pub.prover, proof.commitment.By)) { return false; }
  if (!isValidModN(pub.prover.n, proof.Wy)) { return false; }
  if (!isValidModN(pub.verifier.n, proof.W)) { return false; }

  const point = secp256k1.ProjectivePoint.fromAffine(proof.commitment.Bx);
  // Identity point? TODO: check if this is the right way to do it
  if ((point.px === 0n && point.py === 0n) || point.pz === 0n) { return false; }

  return true;
};

export const zkAffgCreateProof = (
  pub: ZkAffgPublic,
  priv: ZkAffgPrivate,
): ZkAffgProof => {
  const N0 = pub.verifier.n;
  const N1 = pub.prover.n;

  const alpha = sampleIntervalLeps();
  const beta = sampleIntervalLprimeEps();

  const rho = sampleUnitModN(N0);
  const rhoY = sampleUnitModN(N1);

  const gamma = sampleIntervalLepsN();
  const m = sampleIntervalLN();
  const delta = sampleIntervalLepsN();
  const mu = sampleIntervalLN();

  const cAlpha = paillierMultiply(pub.verifier, pub.Kv, alpha);
  const A = paillierAdd(
    pub.verifier,
    paillierEncryptWithNonce(pub.verifier, beta, rho),
    cAlpha,
  );

  const E = pedersenCommit(pub.aux, alpha, gamma);
  const S = pedersenCommit(pub.aux, priv.X, m);
  const F = pedersenCommit(pub.aux, beta, delta);
  const T = pedersenCommit(pub.aux, priv.Y, mu);

  const Bx = secp256k1.ProjectivePoint.BASE.multiply(Fn.mod(alpha)).toAffine();
  const By = paillierEncryptWithNonce(pub.prover, beta, rhoY);

  const commitment: ZkAffgCommitment = { A, Bx, By, E, S, F, T };

  const e = challenge(pub, commitment);

  const Z1 = priv.X * e + alpha;
  const Z2 = priv.Y * e + beta;
  const Z3 = e * m + gamma;
  const Z4 = e * mu + delta;
  const W = modMultiply(
    [
      modPow(priv.S, e, N0),
      rho,
    ],
    N0,
  );
  const Wy = modMultiply(
    [
      modPow(priv.R, e, N1),
      rhoY,
    ],
    N1,
  );

  return {
    commitment, Z1, Z2, Z3, Z4, W, Wy,
  };
}

export const zkAffgVerifyProof = (
  proof: ZkAffgProof,
  pub: ZkAffgPublic,
): boolean => {
  if (!zkAffgIsProofValid(proof, pub)) { return false; }
  if (!isInIntervalLeps(proof.Z1)) { return false; }
  if (!isInIntervalLprimeEps(proof.Z2)) { return false; }

  const e = challenge(pub, proof.commitment);

  if (!pedersenVerify(
    pub.aux, proof.Z1, proof.Z3, e, proof.commitment.E, proof.commitment.S
  )) {
    return false;
  }

  if (!pedersenVerify(
    pub.aux, proof.Z2, proof.Z4, e, proof.commitment.F, proof.commitment.T
  )) {
    return false;
  }

  {
    const lhs = paillierAdd(
      pub.verifier,
      paillierEncryptWithNonce(pub.verifier, proof.Z2, proof.W),
      paillierMultiply(pub.verifier, pub.Kv, proof.Z1),
    );
    const rhs = paillierAdd(
      pub.verifier,
      paillierMultiply(pub.verifier, pub.Dv, e),
      proof.commitment.A,
    );
    if (lhs !== rhs) { return false; }
  }

  {
    const lhs = secp256k1.ProjectivePoint.BASE.multiply(Fn.mod(proof.Z1));

    const pointXp = secp256k1.ProjectivePoint.fromAffine(pub.Xp);
    const pointBx = secp256k1.ProjectivePoint.fromAffine(proof.commitment.Bx);
    const rhs = pointXp.multiply(Fn.mod(e)).add(pointBx);

    if (!lhs.equals(rhs)) {
      return false;
    }
  }

  {
    const lhs = paillierEncryptWithNonce(pub.prover, proof.Z2, proof.Wy);
    const rhs = paillierAdd(
      pub.prover,
      paillierMultiply(pub.prover, pub.Fp, e),
      proof.commitment.By,
    );

    if (lhs !== rhs) { return false; }
  }

  return true;
};

const challenge = (
  pub: ZkAffgPublic,
  commitment: ZkAffgCommitment,
): bigint => {
  const bigHash = Hasher.create().updateMulti([
    pub.aux,
    pub.prover,
    pub.verifier,
    pub.Kv,
    pub.Dv,
    pub.Fp,
    pub.Xp,
    commitment.A,
    commitment.Bx,
    commitment.By,
    commitment.E,
    commitment.S,
    commitment.F,
    commitment.T,
  ]).digestBigint();

  const challenge = Fn.sub(bigHash, 2n ** 255n); // TODO

  return challenge
};
