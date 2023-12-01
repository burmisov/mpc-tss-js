import { modMultiply, modPow } from "bigint-crypto-utils";

import { Hasher } from "../Hasher.js";
import { PedersenParameters, pedersenCommit, pedersenVerify } from "../pedersen.js";
import {
  sampleIntervalLEpsRootN, sampleIntervalLN,
  sampleIntervalLN2, sampleIntervalLepsN,
} from "../sample.js";
import Fn from "../Fn.js";
import { isInIntervalLEpsPlus1RootN } from "../arith.js";

export type ZkFacPublic = {
  N: bigint;
  Aux: PedersenParameters;
};

export type ZkFacPrivate = {
  P: bigint;
  Q: bigint;
};

export type ZkFacCommitment = {
  P: bigint;
  Q: bigint;
  A: bigint;
  B: bigint;
  T: bigint;
};

export type ZkFacProof = {
  comm: ZkFacCommitment;
  sigma: bigint;
  Z1: bigint;
  Z2: bigint;
  W1: bigint;
  W2: bigint;
  V: bigint;
};

export const zkFacCreateProof = (
  priv: ZkFacPrivate,
  pub: ZkFacPublic,
  hasher: Hasher,
): ZkFacProof => {
  const Nhat = pub.Aux.n;

  const alpha = sampleIntervalLEpsRootN();
  const beta = sampleIntervalLEpsRootN();
  const mu = sampleIntervalLN();
  const nu = sampleIntervalLN();
  const sigma = sampleIntervalLN2();
  const r = sampleIntervalLN2();
  const x = sampleIntervalLepsN();
  const y = sampleIntervalLepsN();

  const pInt = priv.P;
  const qInt = priv.Q;
  const P = pedersenCommit(pub.Aux, pInt, mu);
  const Q = pedersenCommit(pub.Aux, qInt, nu);
  const A = pedersenCommit(pub.Aux, alpha, x);
  const B = pedersenCommit(pub.Aux, beta, y);
  const T = modMultiply(
    [
      modPow(Q, alpha, Nhat),
      modPow(pub.Aux.t, r, Nhat),
    ],
    Nhat,
  );

  const comm: ZkFacCommitment = { P, Q, A, B, T };

  const e = challenge(hasher, pub, comm);

  const Z1 = e * pInt + alpha;
  const Z2 = e * qInt + beta;
  const W1 = e * mu + x;
  const W2 = e * nu + y;
  const sigmaHat = -nu * pInt + sigma;
  const V = e * sigmaHat + r;

  return { comm, sigma, Z1, Z2, W1, W2, V };
};

export const zkFacVerifyProof = (
  proof: ZkFacProof,
  pub: ZkFacPublic,
  hasher: Hasher,
): boolean => {
  if (!proof) { return false; }

  const e = challenge(hasher, pub, proof.comm);

  const N0 = pub.N;
  const Nhat = pub.Aux.n;

  if (!pedersenVerify(
    pub.Aux, proof.Z1, proof.W1, e, proof.comm.A, proof.comm.P,
  )) { return false; }

  if (!pedersenVerify(
    pub.Aux, proof.Z2, proof.W2, e, proof.comm.B, proof.comm.Q,
  )) { return false; }

  const R = modMultiply(
    [
      modPow(pub.Aux.s, N0, Nhat),
      modPow(pub.Aux.t, proof.sigma, Nhat),
    ],
    Nhat,
  );
  const lhs = modMultiply(
    [
      modPow(proof.comm.Q, proof.Z1, Nhat),
      modPow(pub.Aux.t, proof.V, Nhat),
    ],
    Nhat,
  );
  const rhs = modMultiply(
    [
      modPow(R, e, Nhat),
      proof.comm.T,
    ],
    Nhat,
  );
  if (lhs !== rhs) { return false; }

  return (isInIntervalLEpsPlus1RootN(proof.Z1)) && (isInIntervalLEpsPlus1RootN(proof.Z2));
}

const challenge = (hasher: Hasher, pub: ZkFacPublic, comm: ZkFacCommitment): bigint => {
  const bigHash = hasher.updateMulti([
    pub.N,
    pub.Aux,
    comm.P,
    comm.Q,
    comm.A,
    comm.B,
    comm.T,
  ]).digestBigint();

  // TODO: not at all sure here 
  const challenge = Fn.sub(bigHash, 2n ** 255n);

  return challenge;
};
