import { secp256k1 } from "@noble/curves/secp256k1";

import { isInIntervalLeps, isValidModN } from "../arith.js";
import { AffinePoint, AffinePointJSON } from "../common.types.js";
import { PaillierPublicKey, paillierAdd, paillierMultiply } from "../paillier.js";
import { PedersenParams } from "../pedersen.js";
import {
  sampleIntervalLN, sampleIntervalLeps, sampleIntervalLepsN,
  sampleUnitModN,
} from "../sample.js";
import Fn from "../Fn.js";
import { Hasher } from "../Hasher.js";
import { modMultiply, modPow } from "bigint-crypto-utils";
import { isIdentity, pointFromJSON, pointToJSON } from "../curve.js";

export type ZkLogstarPublic = {
  C: bigint; // ciphertext
  X: AffinePoint;
  G?: AffinePoint;
  prover: PaillierPublicKey;
  aux: PedersenParams;
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

export type ZkLogstarProofJSON = {
  commitment: {
    Sdec: string,
    Adec: string,
    Y: AffinePointJSON,
    Ddec: string,
  },
  Z1dec: string,
  Z2dec: string,
  Z3dec: string,
};

export class ZkLogstarProof {
  public readonly commitment: ZkLogstarCommitment;
  public readonly Z1: bigint;
  public readonly Z2: bigint;
  public readonly Z3: bigint;

  private constructor(
    commitment: ZkLogstarCommitment,
    Z1: bigint,
    Z2: bigint,
    Z3: bigint,
  ) {
    this.commitment = commitment;
    this.Z1 = Z1;
    this.Z2 = Z2;
    this.Z3 = Z3;
  }

  public static from({
    commitment,
    Z1,
    Z2,
    Z3,
  }: {
    commitment: ZkLogstarCommitment,
    Z1: bigint,
    Z2: bigint,
    Z3: bigint,
  }): ZkLogstarProof {
    const proof = new ZkLogstarProof(commitment, Z1, Z2, Z3);
    Object.freeze(proof);
    return proof;
  }

  public static fromJSON(json: ZkLogstarProofJSON): ZkLogstarProof {
    return ZkLogstarProof.from({
      commitment: {
        S: BigInt(json.commitment.Sdec),
        A: BigInt(json.commitment.Adec),
        Y: pointFromJSON(json.commitment.Y),
        D: BigInt(json.commitment.Ddec),
      },
      Z1: BigInt(json.Z1dec),
      Z2: BigInt(json.Z2dec),
      Z3: BigInt(json.Z3dec),
    });
  }

  public toJSON(): ZkLogstarProofJSON {
    return {
      commitment: {
        Sdec: this.commitment.S.toString(10),
        Adec: this.commitment.A.toString(10),
        Y: pointToJSON(this.commitment.Y),
        Ddec: this.commitment.D.toString(10),
      },
      Z1dec: this.Z1.toString(10),
      Z2dec: this.Z2.toString(10),
      Z3dec: this.Z3.toString(10),
    };
  }
};

export const zkLogstarIsProofValid = (
  proof: ZkLogstarProof,
  pub: ZkLogstarPublic,
): boolean => {
  if (!proof) { return false; }
  if (!pub.prover.validateCiphertext(proof.commitment.A)) { return false; }
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
    A: pub.prover.encryptWithNonce(alpha, r),
    Y: pointG.multiply(Fn.mod(alpha)).toAffine(),
    S: pub.aux.commit(priv.X, mu),
    D: pub.aux.commit(alpha, gamma),
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

  const proof = ZkLogstarProof.from({
    commitment,
    Z1,
    Z2,
    Z3,
  });

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

  if (!pub.aux.verify(proof.Z1, proof.Z3, e, proof.commitment.D, proof.commitment.S)) {
    return false;
  }

  const lhs = pub.prover.encryptWithNonce(proof.Z1, proof.Z2);
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
