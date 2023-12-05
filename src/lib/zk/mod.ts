import {
  bitLength, isProbablyPrime, modInv, modMultiply, modPow,
} from "bigint-crypto-utils";
import { bytesToNumberBE } from "@noble/curves/abstract/utils";

import { isValidModN, jacobi } from "../arith.js";
import { Hasher } from "../Hasher.js";
import { STAT_PARAM, sampleQNR } from "../sample.js";
import { JSONable } from "../serde.js";

export type ZkModPublic = {
  N: bigint;
};

export type ZkModPrivate = {
  P: bigint;
  Q: bigint;
  Phi: bigint;
};

export type ZkModResponse = {
  A: boolean;
  B: boolean;
  X: bigint;
  Z: bigint;
};

export type ZkModProofJSON = {
  Whex: string;
  Responses: Array<{
    A: boolean;
    B: boolean;
    Xhex: string;
    Zhex: string;
  }>;
};

export class ZkModProof implements JSONable {
  public readonly W: bigint;
  public readonly Responses: ZkModResponse[]; // len = STAT_PARAM = 80

  private constructor(W: bigint, Responses: ZkModResponse[]) {
    this.W = W;
    this.Responses = Responses;
  }

  public static from({ W, Responses }: {
    W: bigint,
    Responses: ZkModResponse[],
  }): ZkModProof {
    const p = new ZkModProof(W, Responses);
    Object.freeze(p);
    return p;
  }

  public static fromJSON(json: ZkModProofJSON): ZkModProof {
    const { Whex, Responses } = json;
    const W = BigInt(`0x${Whex}`);
    const rs = Responses.map((r) => {
      const { A, B } = r;
      const X = BigInt(`0x${r.Xhex}`);
      const Z = BigInt(`0x${r.Zhex}`);
      return { A, B, X, Z };
    });
    return ZkModProof.from({ W, Responses: rs });
  }

  public toJSON(): ZkModProofJSON {
    const Responses = this.Responses.map((r) => {
      const { A, B, X, Z } = r;
      return {
        A,
        B,
        Xhex: X.toString(16),
        Zhex: Z.toString(16),
      };
    });
    return {
      Whex: this.W.toString(16),
      Responses,
    };
  }
};

const isQRmodPQ = (
  y: bigint, pHalf: bigint, qHalf: bigint, p: bigint, q: bigint,
): boolean => {
  const pOk = modPow(y, pHalf, p) === 1n;
  const qOk = modPow(y, qHalf, q) === 1n;
  return pOk && qOk;
}

export const zkModFourthRootExponent = (phi: bigint): bigint => {
  const e_ = (phi + 4n) / 8n;
  const e = modMultiply([e_, e_], phi);
  return e;
}

export const zkModMakeQuadraticResidue = (
  y: bigint, w: bigint, pHalf: bigint, qHalf: bigint, n: bigint, p: bigint, q: bigint,
): { a: boolean, b: boolean, out: bigint } => {
  let out = y % n;
  let a = false;
  let b = false;
  if (isQRmodPQ(out, pHalf, qHalf, p, q)) {
    return { a, b, out };
  }

  // multiply by -1
  out = modMultiply([out, -1n], n);
  a = true;
  b = false;
  if (isQRmodPQ(out, pHalf, qHalf, p, q)) {
    return { a, b, out };
  }

  // multiply by w again
  out = modMultiply([out, w], n);
  a = true;
  b = true;
  if (isQRmodPQ(out, pHalf, qHalf, p, q)) {
    return { a, b, out };
  }

  // multiply by -1 again
  out = modMultiply([out, -1n], n);
  a = false;
  b = true;
  return { a, b, out };
};

export const zkModIsProofValid = (proof: ZkModProof, pub: ZkModPublic): boolean => {
  if (!proof) { return false; }
  if (jacobi(proof.W, pub.N) !== -1) { return false; }
  if (!isValidModN(pub.N, proof.W)) { return false; }
  for (const r of proof.Responses) {
    if (!isValidModN(pub.N, r.X)) { return false; }
    if (!isValidModN(pub.N, r.Z)) { return false; }
  }
  return true;
};

export const zkModCreateProof = (
  priv: ZkModPrivate, pub: ZkModPublic, hasher: Hasher,
): ZkModProof => {
  const { N: n } = pub;
  const { P: p, Q: q, Phi: phi } = priv;
  const pHalf = p >> 1n;
  const qHalf = q >> 1n;
  const w = sampleQNR(n);

  const nInverse = modInv(n, phi);

  const e = zkModFourthRootExponent(phi);

  const ys = zkModChallenge(hasher, n, w);

  const rs: ZkModResponse[] = ys.map((y) => {
    const Z = modPow(y, nInverse, n);

    const { a: A, b: B, out: yPrime } = zkModMakeQuadraticResidue(y, w, pHalf, qHalf, n, p, q);
    const X = modPow(yPrime, e, n);

    return { A, B, X, Z };
  });

  return ZkModProof.from({ W: w, Responses: rs });
};

const verifyResponse = (
  r: ZkModResponse, n: bigint, w: bigint, y: bigint,
): boolean => {
  let lhs = modPow(r.Z, n, n);

  if (lhs !== y) { return false; }

  lhs = modMultiply([r.X, r.X, r.X, r.X], n);

  let rhs = y;
  if (r.A) { rhs = modMultiply([rhs, -1n], n); }
  if (r.B) { rhs = modMultiply([rhs, w], n); }

  return lhs === rhs;
};

export const zkModVerifyProof = async (
  proof: ZkModProof, pub: ZkModPublic, hasher: Hasher,
): Promise<boolean> => {
  if (!proof) { return false; }

  const { N: n } = pub;
  if (n % 2n === 0n) { return false; }

  if (await isProbablyPrime(n, 20)) { return false; }

  if (jacobi(proof.W, n) !== -1) { return false; }

  if (!isValidModN(n, proof.W)) { return false; }

  const ys = zkModChallenge(hasher, n, proof.W);

  const { W: w, Responses: rs } = proof;

  const verifications = rs.map((r, i) => {
    return verifyResponse(r, n, w, ys[i]);
  });

  return verifications.every((v) => v);
}

// TODO: Needs checking
export const zkModChallenge = (hasher: Hasher, n: bigint, w: bigint): bigint[] => {
  hasher.updateMulti([n, w]);

  const bytesPerSample = Math.floor(bitLength(n) / 8) + 2; // TODO: why +2?
  const digestBytes = new Uint8Array(bytesPerSample * STAT_PARAM);
  hasher.digestBytesInto(digestBytes);

  const es: bigint[] = [];
  for (let i = 0; i < STAT_PARAM; i += 1) {
    const offset = i * bytesPerSample;
    const bytes = digestBytes.slice(offset, offset + bytesPerSample);
    const e_ = bytesToNumberBE(bytes);
    const e = e_ % n;
    es.push(e);
  }

  return es;
};
