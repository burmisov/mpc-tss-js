import { modMultiply, modPow } from "bigint-crypto-utils";

import Fn from "../Fn.js";
import { isValidModN, isInIntervalLeps } from "../arith.js";
import { PaillierPublicKey, paillierAdd, paillierMultiply } from "../paillier.js";
import { PedersenParams } from "../pedersen.js";
import {
  sampleUnitModN, sampleIntervalLeps, sampleIntervalLN,
  sampleIntervalLepsN
} from "../sample.js";
import { Hasher } from "../Hasher.js";

export type ZkEncPublic = {
  K: bigint, // Paillier ciphertext
  prover: PaillierPublicKey,
  aux: PedersenParams,
};

export type ZkEncPrivate = {
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
  pub: ZkEncPublic,
  priv: ZkEncPrivate,
  hasher: Hasher,
): ZkEncProof => {
  const alpha = sampleIntervalLeps();
  const r = sampleUnitModN(pub.prover.n);
  const mu = sampleIntervalLN();
  const gamma = sampleIntervalLepsN();

  const A = pub.prover.encryptWithNonce(alpha, r);

  const commitment: ZkEncCommitment = {
    S: pub.aux.commit(priv.k, mu),
    A,
    C: pub.aux.commit(alpha, gamma),
  };

  const e = challenge(pub, commitment, hasher);

  const Z1 = priv.k * e + alpha;
  const Z2 = modMultiply(
    [
      modPow(priv.rho, e, pub.prover.n),
      r,
    ],
    pub.prover.n
  )
  const Z3 = e * mu + gamma;

  return {
    commitment,
    Z1, Z2, Z3,
  };
};

export const zkEncVerifyProof = (
  proof: ZkEncProof,
  pub: ZkEncPublic,
  hasher: Hasher,
): boolean => {
  if (!zkEncIsPublicValid(proof, pub)) { return false; }
  if (!isInIntervalLeps(proof.Z1)) { return false; }

  const e = challenge(pub, proof.commitment, hasher);
  if (!pub.aux.verify(proof.Z1, proof.Z3, e, proof.commitment.C, proof.commitment.S)) {
    return false;
  }

  const lhs = pub.prover.encryptWithNonce(proof.Z1, proof.Z2);
  const rhs = paillierAdd(
    pub.prover,
    paillierMultiply(pub.prover, pub.K, e),
    proof.commitment.A
  );

  return lhs === rhs;
}

export const zkEncIsPublicValid = (
  proof: ZkEncProof,
  pub: ZkEncPublic,
): boolean => {
  if (!proof) { return false; }
  if (!pub.prover.validateCiphertext(proof.commitment.A)) { return false; }
  if (!isValidModN(pub.prover.n, proof.Z2)) { return false; }
  return true;
}

const challenge = (
  pub: ZkEncPublic,
  commitment: ZkEncCommitment,
  hasher: Hasher,
): bigint => {
  const bigHash = hasher.updateMulti([
    pub.aux,
    pub.prover,
    pub.K,
    commitment.S,
    commitment.A,
    commitment.C,
  ]).digestBigint();

  const challenge = Fn.sub(bigHash, 2n ** 255n); // TODO

  return challenge
}
