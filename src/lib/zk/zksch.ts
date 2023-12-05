import { secp256k1 } from "@noble/curves/secp256k1";

import { Hasher } from "../Hasher.js";
import { AffinePoint, AffinePointJSON } from "../common.types.js";
import { sampleScalar } from "../sample.js";
import { isIdentity, pointFromJSON, pointToJSON } from "../curve.js";
import Fn from "../Fn.js";
import { JSONable } from "../serde.js";

export type ZkSchRandomness = {
  a: bigint,
  commitment: ZkSchCommitment,
};

export type ZkSchResponseJSON = {
  Zhex: string;
};

export class ZkSchResponse implements JSONable {
  public readonly Z: bigint;

  private constructor(Z: bigint) {
    this.Z = Z;
  }

  public static from({ Z }: { Z: bigint }): ZkSchResponse {
    const c = new ZkSchResponse(Z);
    Object.freeze(c);
    return c;
  }

  public toJSON(): ZkSchResponseJSON {
    return {
      Zhex: this.Z.toString(16),
    };
  }

  public static fromJSON(json: ZkSchResponseJSON): ZkSchResponse {
    return ZkSchResponse.from({
      Z: BigInt(`0x${json.Zhex}`),
    });
  }
};

export type ZkSchCommitmentJSON = {
  C: AffinePointJSON;
};

export class ZkSchCommitment implements JSONable {
  public readonly C: AffinePoint;

  private constructor(C: AffinePoint) {
    this.C = C;
  }

  public static from({ C }: { C: AffinePoint }): ZkSchCommitment {
    const c = new ZkSchCommitment(C);
    Object.freeze(c);
    return c;
  }

  public toJSON(): ZkSchCommitmentJSON {
    return {
      C: pointToJSON(this.C),
    };
  }

  public static fromJSON(json: ZkSchCommitmentJSON): ZkSchCommitment {
    return ZkSchCommitment.from({
      C: pointFromJSON(json.C),
    });
  }
};

export type ZkSchProof = {
  C: ZkSchCommitment,
  Z: ZkSchResponse,
};

export const zkSchCreateProof = (
  hasher: Hasher,
  pubPoint: AffinePoint,
  priv: bigint,
  gen: AffinePoint,
): ZkSchProof | null => {
  const a = zkSchCreateRandomness(gen);
  const Z = zkSchProve(a, hasher, pubPoint, priv, gen);

  if (!Z) { return null; };

  return {
    C: a.commitment,
    Z,
  }
}

export const zkSchCreateRandomness = (genIn?: AffinePoint): ZkSchRandomness => {
  const gen = genIn ?
    secp256k1.ProjectivePoint.fromAffine(genIn) :
    secp256k1.ProjectivePoint.BASE;
  const a = sampleScalar();
  const commitment = ZkSchCommitment.from({
    C: gen.multiply(a).toAffine(),
  });
  return { a, commitment };
}

const challenge = (
  hasher: Hasher,
  commitment: ZkSchCommitment,
  pubPoint: AffinePoint,
  gen: AffinePoint,
): bigint => {
  const bigHash = hasher.updateMulti([
    commitment.C,
    pubPoint,
    gen,
  ]).digestBigint();

  const challenge = Fn.sub(bigHash, 2n ** 255n); // TODO

  return challenge;
};

export const zkSchProve = (
  r: ZkSchRandomness,
  hasher: Hasher,
  pubPoint: AffinePoint,
  secret: bigint,
  genIn?: AffinePoint,
): ZkSchResponse | null => {
  const gen = genIn ?
    secp256k1.ProjectivePoint.fromAffine(genIn) :
    secp256k1.ProjectivePoint.BASE;

  if (isIdentity(secp256k1.ProjectivePoint.fromAffine(pubPoint)) || secret === 0n) {
    return null;
  }

  const e = challenge(hasher, r.commitment, pubPoint, gen);
  const es = Fn.mul(e, secret);
  const Z = Fn.add(es, r.a);

  return ZkSchResponse.from({ Z });
};

export const zkSchVerifyResponse = (
  z: ZkSchResponse,
  hasher: Hasher,
  pubPoint: AffinePoint,
  commitment: ZkSchCommitment,
  genIn?: AffinePoint,
): boolean => {
  const gen = genIn ?
    secp256k1.ProjectivePoint.fromAffine(genIn) :
    secp256k1.ProjectivePoint.BASE;

  const pubPointProj = secp256k1.ProjectivePoint.fromAffine(pubPoint);
  if (!z || !zkSchIsResponseValid(z) || isIdentity(pubPointProj)) {
    return false;
  }

  const e = challenge(hasher, commitment, pubPoint, gen);

  const lhs = gen.multiply(z.Z);
  const rhs = pubPointProj.multiply(e).add(
    secp256k1.ProjectivePoint.fromAffine(commitment.C),
  );

  return lhs.equals(rhs);
}

export const zkSchVerifyProof = (
  p: ZkSchProof,
  hasher: Hasher,
  pubPoint: AffinePoint,
  genIn: AffinePoint,
): boolean => {
  if (!zkSchIsProofValid(p)) { return false; }
  return zkSchVerifyResponse(p.Z, hasher, pubPoint, p.C, genIn);
}

const zkSchIsCommitmentValid = (c: ZkSchCommitment): boolean => {
  if (!c || isIdentity(secp256k1.ProjectivePoint.fromAffine(c.C))) {
    return false;
  }
  return true;
}

export const zkSchIsResponseValid = (z: ZkSchResponse): boolean => {
  if (!z || z.Z === 0n) {
    return false;
  }
  return true;
}

const zkSchIsProofValid = (p: ZkSchProof): boolean => {
  if (!p || !zkSchIsResponseValid(p.Z) || !zkSchIsCommitmentValid(p.C)) {
    return false;
  }
  return true;
}
