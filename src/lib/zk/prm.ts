import { modAdd, modMultiply, modPow } from "bigint-crypto-utils";

import { Hasher } from "../Hasher.js";
import { isValidModN } from "../arith.js";
import { PedersenParams } from "../pedersen.js";
import { STAT_PARAM, sampleModN } from "../sample.js";
import { JSONable } from "../serde.js";

export type ZkPrmPublic = {
  Aux: PedersenParams;
};

export type ZkPrmPrivate = {
  Lambda: bigint;
  Phi: bigint;
  P: bigint;
  Q: bigint;
};

export type ZkPrmProofJSON = {
  AsHex: string[];
  ZsHex: string[];
};

export class ZkPrmProof implements JSONable {
  public readonly As: bigint[]; // size StatParam = 80
  public readonly Zs: bigint[]; // size StatParam = 80

  private constructor(As: bigint[], Zs: bigint[]) {
    this.As = As;
    this.Zs = Zs;
  }

  public static from({ As, Zs }: { As: bigint[], Zs: bigint[] }): ZkPrmProof {
    const p = new ZkPrmProof(As, Zs);
    Object.freeze(p);
    return p;
  }

  public static fromJSON(json: ZkPrmProofJSON): ZkPrmProof {
    const { AsHex, ZsHex } = json;
    const As = AsHex.map((h) => BigInt(`0x${h}`));
    const Zs = ZsHex.map((h) => BigInt(`0x${h}`));
    return ZkPrmProof.from({ As, Zs });
  }

  public toJSON(): ZkPrmProofJSON {
    const AsHex = this.As.map((a) => a.toString(16));
    const ZsHex = this.Zs.map((z) => z.toString(16));
    return { AsHex, ZsHex };
  }
};

export const zkPrmIsProofValid = (proof: ZkPrmProof, pub: ZkPrmPublic): boolean => {
  if (!proof) { return false; }
  for (let i = 0; i < proof.As.length; i += 1) {
    if (!isValidModN(pub.Aux.n, proof.As[i])) { return false; }
    if (!isValidModN(pub.Aux.n, proof.Zs[i])) { return false; }
  }
  return true;
}

export const zkPrmCreateProof = (
  priv: ZkPrmPrivate, pub: ZkPrmPublic, hasher: Hasher,
): ZkPrmProof => {
  const lambda = priv.Lambda;
  const phi = priv.Phi;
  const n = priv.P * priv.Q;
  const as: bigint[] = [];
  const As: bigint[] = [];

  for (let i = 0; i < STAT_PARAM; i += 1) {
    as.push(sampleModN(phi));
    As.push(modPow(pub.Aux.t, as[i], n));
  }

  const es = challenge(hasher, pub, As);

  const Zs: bigint[] = [];
  for (let i = 0; i < STAT_PARAM; i += 1) {
    let z = as[i];
    if (es[i]) {
      z = modAdd([z, lambda], phi);
    }
    Zs.push(z);
  }

  return ZkPrmProof.from({ As, Zs });
}

export const zkPrmVerifyProof = (
  proof: ZkPrmProof, pub: ZkPrmPublic, hasher: Hasher,
): boolean => {
  if (!proof) { return false; }
  try {
    pub.Aux.validate();
  } catch (e) {
    return false;
  }

  const { n, s, t } = pub.Aux;

  const es = challenge(hasher, pub, proof.As);

  const verifications: boolean[] = [];

  for (let i = 0; i < STAT_PARAM; i += 1) {
    const z = proof.Zs[i];
    const a = proof.As[i];

    if (!isValidModN(n, a)) { verifications.push(false); continue; }
    if (!isValidModN(n, z)) { verifications.push(false); continue; }

    if (a === 1n) { verifications.push(false); continue; }

    const lhs = modPow(t, z, n);
    const rhs = es[i] ? modMultiply([a, s], n) : a;
    if (lhs !== rhs) { verifications.push(false); continue; }

    verifications.push(true);
  }

  return verifications.every((v) => v);
}

const challenge = (hasher: Hasher, pub: ZkPrmPublic, A: bigint[]): boolean[] => {
  hasher.update(pub.Aux);
  for (const a of A) { hasher.update(a); }
  const tmpBytes = new Uint8Array(STAT_PARAM);
  hasher.digestBytesInto(tmpBytes);
  const es: boolean[] = [];
  for (let i = 0; i < STAT_PARAM; i += 1) {
    const b = (tmpBytes[i] & 1) === 1;
    es.push(b);
  }
  return es;
}
