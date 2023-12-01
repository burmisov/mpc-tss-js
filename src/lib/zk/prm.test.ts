import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  paillierGeneratePedersen, paillierSecretKeyFromPrimes, validatePaillierPrime,
} from '../paillier.js';
import { Hasher } from '../Hasher.js';
import {
  ZkPrmPrivate, ZkPrmPublic,
  zkPrmCreateProof, zkPrmIsProofValid, zkPrmVerifyProof,
} from './prm.js';

test('zk/prm', async () => {
  const p = 167495246782569910107862669897619243075835098207853220101403982609959943903743345646375788362909715211900141652671436007095125366426921092792005772260273820630537327116191279465491203987638225198595642843240698088777581339844121640128731583440776342448939839731522446469995390448902946229002446098530004835239n;
  const q = 178784929586423449637890491161861655617854412540709400421874212815293580828404739498291345696103341491924297140261396221041987821086550770172144419152711267591283272834659746554330603868249176073673884285246036132552905332762099384955889000396765335249879642433930458968871576233738650973235318810378637560383n;
  await validatePaillierPrime(p);
  await validatePaillierPrime(q);
  const paillierSecretKey = paillierSecretKeyFromPrimes(p, q);
  const { pedersen, lambda } = paillierGeneratePedersen(paillierSecretKey);

  const hasher = Hasher.create().update('test');

  const pub: ZkPrmPublic = {
    Aux: pedersen,
  };
  const priv: ZkPrmPrivate = {
    Lambda: lambda,
    Phi: paillierSecretKey.phi,
    P: paillierSecretKey.p,
    Q: paillierSecretKey.q,
  };

  const proof = zkPrmCreateProof(priv, pub, hasher.clone());

  const valid = zkPrmIsProofValid(proof, pub);
  assert(valid, 'failed to validate zkPrm proof');

  const verified = zkPrmVerifyProof(proof, pub, hasher.clone());
  assert(verified, 'failed to verify zkPrm proof');
});
