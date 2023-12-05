import { modMultiply, modPow } from "bigint-crypto-utils";

import { Hasher } from "../Hasher.js";
import { PedersenParams } from "../pedersen.js";
import {
  sampleIntervalLEpsRootN, sampleIntervalLN,
  sampleIntervalLN2, sampleIntervalLepsN,
} from "../sample.js";
import Fn from "../Fn.js";
import { isInIntervalLEpsPlus1RootN } from "../arith.js";

export type ZkFacPublic = {
  N: bigint;
  Aux: PedersenParams;
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

export type ZkFacProofJSON = {
  comm: {
    Pdec: string;
    Qdec: string;
    Adec: string;
    Bdec: string;
    Tdec: string;
  },
  sigmaDec: string;
  Z1dec: string;
  Z2dec: string;
  W1dec: string;
  W2dec: string;
  Vdec: string;
};

export class ZkFacProof {
  public readonly comm: ZkFacCommitment;
  public readonly sigma: bigint;
  public readonly Z1: bigint;
  public readonly Z2: bigint;
  public readonly W1: bigint;
  public readonly W2: bigint;
  public readonly V: bigint;

  private constructor(
    comm: ZkFacCommitment,
    sigma: bigint,
    Z1: bigint,
    Z2: bigint,
    W1: bigint,
    W2: bigint,
    V: bigint,
  ) {
    this.comm = comm;
    this.sigma = sigma;
    this.Z1 = Z1;
    this.Z2 = Z2;
    this.W1 = W1;
    this.W2 = W2;
    this.V = V;
  }

  public static from({ comm, sigma, Z1, Z2, W1, W2, V }: {
    comm: ZkFacCommitment,
    sigma: bigint,
    Z1: bigint,
    Z2: bigint,
    W1: bigint,
    W2: bigint,
    V: bigint,
  }): ZkFacProof {
    const p = new ZkFacProof(comm, sigma, Z1, Z2, W1, W2, V);
    Object.freeze(p);
    return p;
  }

  public static fromJSON(json: ZkFacProofJSON): ZkFacProof {
    const { comm, sigmaDec, Z1dec, Z2dec, W1dec, W2dec, Vdec } = json;
    const P = BigInt(comm.Pdec);
    const Q = BigInt(comm.Qdec);
    const A = BigInt(comm.Adec);
    const B = BigInt(comm.Bdec);
    const T = BigInt(comm.Tdec);
    const commObj: ZkFacCommitment = { P, Q, A, B, T };
    const sigma = BigInt(sigmaDec);
    const Z1 = BigInt(Z1dec);
    const Z2 = BigInt(Z2dec);
    const W1 = BigInt(W1dec);
    const W2 = BigInt(W2dec);
    const V = BigInt(Vdec);
    return ZkFacProof.from({ comm: commObj, sigma, Z1, Z2, W1, W2, V });
  }

  public toJSON(): ZkFacProofJSON {
    const { P, Q, A, B, T } = this.comm;
    const Pdec = P.toString(10);
    const Qdec = Q.toString(10);
    const Adec = A.toString(10);
    const Bdec = B.toString(10);
    const Tdec = T.toString(10);
    const sigmaDec = this.sigma.toString(10);
    const Z1dec = this.Z1.toString(10);
    const Z2dec = this.Z2.toString(10);
    const W1dec = this.W1.toString(10);
    const W2dec = this.W2.toString(10);
    const Vdec = this.V.toString(10);
    return {
      comm: { Pdec, Qdec, Adec, Bdec, Tdec },
      sigmaDec, Z1dec, Z2dec, W1dec, W2dec, Vdec,
    };
  }
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
  const P = pub.Aux.commit(pInt, mu);
  const Q = pub.Aux.commit(qInt, nu);
  const A = pub.Aux.commit(alpha, x);
  const B = pub.Aux.commit(beta, y);
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

  return ZkFacProof.from({ comm, sigma, Z1, Z2, W1, W2, V });
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

  if (!pub.Aux.verify(proof.Z1, proof.W1, e, proof.comm.A, proof.comm.P)) {
    return false;
  }

  if (!pub.Aux.verify(proof.Z2, proof.W2, e, proof.comm.B, proof.comm.Q)) {
    return false;
  }

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
