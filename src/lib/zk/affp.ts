import { modMultiply, modPow } from "bigint-crypto-utils";

import Fn from "../Fn.js";
import { Hasher } from "../Hasher.js";
import { isInIntervalLeps, isInIntervalLprimeEps, isValidModN } from "../arith.js";
import {
  PaillierPublicKey, paillierAdd, paillierEncryptWithNonce,
  paillierMultiply, validateCiphertext,
} from "../paillier.js";
import { PedersenParameters, pedersenCommit, pedersenVerify } from "../pedersen.js";
import {
  sampleIntervalLN, sampleIntervalLeps, sampleIntervalLepsN,
  sampleIntervalLprimeEps, sampleUnitModN,
} from "../sample.js";

export type ZkAffpPublic = {
  Kv: bigint; // Ciphertext
  Dv: bigint; // Ciphertext
  Fp: bigint; // Ciphertext
  Xp: bigint; // Ciphertext
  prover: PaillierPublicKey;
  verifier: PaillierPublicKey;
  aux: PedersenParameters;
};

export type ZkAffpPrivate = {
  X: bigint;
  Y: bigint;
  S: bigint;
  Rx: bigint;
  R: bigint;
};

export type ZkAffpCommitment = {
  A: bigint; // Ciphertext
  Bx: bigint; // Ciphertext
  By: bigint; // Ciphertext
  E: bigint;
  S: bigint;
  F: bigint;
  T: bigint;
};

export type ZkAffpProof = {
  commitment: ZkAffpCommitment;
  Z1: bigint;
  Z2: bigint;
  Z3: bigint;
  Z4: bigint;
  W: bigint;
  Wx: bigint;
  Wy: bigint;
};

const isValid = (proof: ZkAffpProof, pub: ZkAffpPublic): boolean => {
  if (!proof) { return false; }
  if (!validateCiphertext(pub.verifier, proof.commitment.A)) { return false; }
  if (!validateCiphertext(pub.prover, proof.commitment.Bx)) { return false; }
  if (!validateCiphertext(pub.prover, proof.commitment.By)) { return false; }
  if (!isValidModN(pub.prover.n, proof.Wx)) { return false; }
  if (!isValidModN(pub.prover.n, proof.Wy)) { return false; }
  if (!isValidModN(pub.verifier.n, proof.W)) { return false; }
  return true;
};

export const zkAffpCreateProof = (
  pub: ZkAffpPublic,
  priv: ZkAffpPrivate,
  hasher: Hasher,
): ZkAffpProof => {
  const N0 = pub.verifier.n;
  const N1 = pub.prover.n;

  const alpha = sampleIntervalLeps();
  const beta = sampleIntervalLprimeEps();

  const rho = sampleUnitModN(N0);
  const rhoX = sampleUnitModN(N1);
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

  const Bx = paillierEncryptWithNonce(pub.prover, alpha, rhoX);
  const By = paillierEncryptWithNonce(pub.prover, beta, rhoY);

  const commitment: ZkAffpCommitment = { A, Bx, By, E, S, F, T };

  const e = challenge(pub, commitment, hasher);

  const Z1 = priv.X * e + alpha;
  const Z2 = priv.Y * e + beta;
  const Z3 = m * e + gamma;
  const Z4 = mu * e + delta;
  const W = modMultiply([modPow(priv.S, e, N0), rho], N0);
  const Wx = modMultiply([modPow(priv.Rx, e, N1), rhoX], N1);
  const Wy = modMultiply([modPow(priv.R, e, N1), rhoY], N1);

  return { commitment, Z1, Z2, Z3, Z4, W, Wx, Wy };
};

export const zkAffpVerifyProof = (
  proof: ZkAffpProof,
  pub: ZkAffpPublic,
  hasher: Hasher,
): boolean => {
  if (!isValid(proof, pub)) { return false; }

  if (!isInIntervalLeps(proof.Z1)) { return false; }
  if (!isInIntervalLprimeEps(proof.Z2)) { return false; }

  const e = challenge(pub, proof.commitment, hasher);

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
    const lhs = paillierEncryptWithNonce(pub.prover, proof.Z1, proof.Wx);
    const rhs = paillierAdd(
      pub.prover,
      paillierMultiply(pub.prover, pub.Xp, e),
      proof.commitment.Bx,
    );
    if (lhs !== rhs) { return false; }
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

  return true;
};

const challenge = (
  pub: ZkAffpPublic,
  commitment: ZkAffpCommitment,
  hasher: Hasher,
): bigint => {
  const bigHash = hasher.updateMulti([
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
