import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { secp256k1 } from "@noble/curves/secp256k1";
import { randBetween } from "bigint-crypto-utils";

import {
  PaillierPublicKey, PaillierSecretKey,
  paillierDecrypt, paillierEncrypt, paillierGeneratePedersen,
  paillierSecretKeyFromPrimes, validatePaillierPrime,
} from "./paillier.js";
import { PedersenParameters } from "./pedersen.js";
import Fn from "./Fn.js";
import { mtaProveAffG, mtaProveAffP } from "./mta.js";
import { ZkAffgPublic, zkAffgVerifyProof } from "./zk/affg.js";
import { ZkAffpPublic, zkAffpVerifyProof } from "./zk/affp.js";
import { Hasher } from "./Hasher.js";

describe('mta', async () => {
  let proverPaillierSecretKey: PaillierSecretKey;
  let proverPaillierPublicKey: PaillierPublicKey;
  let verifierPaillierSecretKey: PaillierSecretKey;
  let verifierPaillierPublicKey: PaillierPublicKey;
  let verifierPedersen: PedersenParameters;

  {
    const p = 167495246782569910107862669897619243075835098207853220101403982609959943903743345646375788362909715211900141652671436007095125366426921092792005772260273820630537327116191279465491203987638225198595642843240698088777581339844121640128731583440776342448939839731522446469995390448902946229002446098530004835239n;
    const q = 178784929586423449637890491161861655617854412540709400421874212815293580828404739498291345696103341491924297140261396221041987821086550770172144419152711267591283272834659746554330603868249176073673884285246036132552905332762099384955889000396765335249879642433930458968871576233738650973235318810378637560383n;
    await validatePaillierPrime(p);
    await validatePaillierPrime(q);
    proverPaillierSecretKey = paillierSecretKeyFromPrimes(p, q);
    proverPaillierPublicKey = proverPaillierSecretKey.publicKey;
  }

  {
    const p = 179592502110335963336347735108907147317760904272746519157588428198851642173043932077383231024080457777437444199308940940528740158020956955835017958704625931695110457545843284994471316520797998498062474296013358438785968440081020607611888287234488233606613994066898948321434201732737366068220153564935475802567n;
    const q = 144651337722999591357894368476987413731327694772730408677878934803626218325763401733049627551150267745019646164141178748986827450041894571742897062718616997949877925740444144291875968298065299373438319317040746398994377200405476019627025944607850551945311780131978961657839712750089596117856255513589953855963n;
    await validatePaillierPrime(p);
    await validatePaillierPrime(q);
    verifierPaillierSecretKey = paillierSecretKeyFromPrimes(p, q);
    verifierPaillierPublicKey = verifierPaillierSecretKey.publicKey;
    const { pedersen } = paillierGeneratePedersen(verifierPaillierSecretKey);
    verifierPedersen = pedersen;
  }

  const paillierI = proverPaillierPublicKey;
  const paillierJ = verifierPaillierPublicKey;

  const ski = proverPaillierSecretKey;
  const skj = verifierPaillierSecretKey;
  const ai = randBetween(Fn.N - 1n);
  const aj = randBetween(Fn.N - 1n);

  const bi = randBetween(Fn.N - 1n);
  const bj = randBetween(Fn.N - 1n);

  const { ciphertext: Bi } = paillierEncrypt(paillierI, bi);
  const { ciphertext: Bj } = paillierEncrypt(paillierJ, bj);

  const aibj = Fn.mul(ai, bj);
  const ajbi = Fn.mul(aj, bi);
  const c = Fn.add(aibj, ajbi);

  const verifyMta = (
    Di: bigint, // Ciphertext
    Dj: bigint, // Ciphertext
    betaI: bigint,
    betaJ: bigint,
  ) => {
    const alphaI = paillierDecrypt(ski, Dj);
    const alphaJ = paillierDecrypt(skj, Di);

    const gammaI = alphaI + betaI;
    const gammaJ = alphaJ + betaJ;
    const gamma = gammaI + gammaJ;
    const gammaS = Fn.mod(gamma);

    assert.strictEqual(c, gammaS, "a•b should be equal to α + β");
  }

  it('proves AffG', () => {
    const hasher = Hasher.create().update('test');

    const Ai = secp256k1.ProjectivePoint.BASE.multiply(ai).toAffine();
    const Aj = secp256k1.ProjectivePoint.BASE.multiply(aj).toAffine();

    const {
      Beta: betaI, D: Di, F: Fi, proof: proofI,
    } = mtaProveAffG(
      ai, Ai, Bj, ski, paillierJ, verifierPedersen, hasher.clone(),
    );
    const {
      Beta: betaJ, D: Dj, F: Fj, proof: proofJ,
    } = mtaProveAffG(
      aj, Aj, Bi, skj, paillierI, verifierPedersen, hasher.clone(),
    );

    const pubI: ZkAffgPublic = {
      Kv: Bj,
      Dv: Di,
      Fp: Fi,
      Xp: Ai,
      prover: paillierI,
      verifier: paillierJ,
      aux: verifierPedersen,
    };
    const verifiedI = zkAffgVerifyProof(proofI, pubI, hasher.clone(),);
    assert.strictEqual(verifiedI, true, "Proof I verification failed");

    const pubJ: ZkAffgPublic = {
      Kv: Bi,
      Dv: Dj,
      Fp: Fj,
      Xp: Aj,
      prover: paillierJ,
      verifier: paillierI,
      aux: verifierPedersen,
    };
    const verifiedJ = zkAffgVerifyProof(proofJ, pubJ, hasher.clone(),);
    assert.strictEqual(verifiedJ, true, "Proof J verification failed");

    verifyMta(Di, Dj, betaI, betaJ);
  });

  it('proves AffP', () => {
    const hasher = Hasher.create().update('test');

    const { ciphertext: Ai, nonce: nonceI } = paillierEncrypt(ski.publicKey, ai);
    const { ciphertext: Aj, nonce: nonceJ } = paillierEncrypt(skj.publicKey, aj);
    const {
      Beta: betaI, D: Di, F: Fi, proof: proofI,
    } = mtaProveAffP(
      ai, Ai, nonceI, Bj, ski, paillierJ, verifierPedersen, hasher.clone(),
    );
    const {
      Beta: betaJ, D: Dj, F: Fj, proof: proofJ,
    } = mtaProveAffP(
      aj, Aj, nonceJ, Bi, skj, paillierI, verifierPedersen, hasher.clone(),
    );

    const pubI: ZkAffpPublic = {
      Kv: Bj,
      Dv: Di,
      Fp: Fi,
      Xp: Ai,
      prover: paillierI,
      verifier: paillierJ,
      aux: verifierPedersen,
    };
    const verifiedI = zkAffpVerifyProof(proofI, pubI, hasher.clone());
    assert.strictEqual(verifiedI, true, "Proof I verification failed");

    const pubJ: ZkAffpPublic = {
      Kv: Bi,
      Dv: Dj,
      Fp: Fj,
      Xp: Aj,
      prover: paillierJ,
      verifier: paillierI,
      aux: verifierPedersen,
    };
    const verifiedJ = zkAffpVerifyProof(proofJ, pubJ, hasher.clone());
    assert.strictEqual(verifiedJ, true, "Proof J verification failed");

    verifyMta(Di, Dj, betaI, betaJ);
  });
});
