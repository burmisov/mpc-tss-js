import { test } from 'node:test';
import assert from 'node:assert/strict';

import { PaillierPublicKey, PaillierSecretKey } from '../paillier.js';
import { validatePaillierPrime } from '../paillierKeygen.js';
import { ZkFacPrivate, ZkFacPublic, zkFacCreateProof, zkFacVerifyProof } from './fac.js';
import { Hasher } from '../Hasher.js';
import { PedersenParams } from '../pedersen.js';

test('zk/fac', async () => {
  let proverPaillierSecretKey: PaillierSecretKey;
  let proverPaillierPublicKey: PaillierPublicKey;
  let verifierPaillierSecretKey: PaillierSecretKey;
  let verifierPaillierPublicKey: PaillierPublicKey;
  let verifierPedersen: PedersenParams;

  {
    const p = 167495246782569910107862669897619243075835098207853220101403982609959943903743345646375788362909715211900141652671436007095125366426921092792005772260273820630537327116191279465491203987638225198595642843240698088777581339844121640128731583440776342448939839731522446469995390448902946229002446098530004835239n;
    const q = 178784929586423449637890491161861655617854412540709400421874212815293580828404739498291345696103341491924297140261396221041987821086550770172144419152711267591283272834659746554330603868249176073673884285246036132552905332762099384955889000396765335249879642433930458968871576233738650973235318810378637560383n;
    await validatePaillierPrime(p);
    await validatePaillierPrime(q);
    proverPaillierSecretKey = PaillierSecretKey.fromPrimes(p, q);
    proverPaillierPublicKey = proverPaillierSecretKey.publicKey;
  }

  {
    const p = 179592502110335963336347735108907147317760904272746519157588428198851642173043932077383231024080457777437444199308940940528740158020956955835017958704625931695110457545843284994471316520797998498062474296013358438785968440081020607611888287234488233606613994066898948321434201732737366068220153564935475802567n;
    const q = 144651337722999591357894368476987413731327694772730408677878934803626218325763401733049627551150267745019646164141178748986827450041894571742897062718616997949877925740444144291875968298065299373438319317040746398994377200405476019627025944607850551945311780131978961657839712750089596117856255513589953855963n;
    await validatePaillierPrime(p);
    await validatePaillierPrime(q);
    verifierPaillierSecretKey = PaillierSecretKey.fromPrimes(p, q);
    verifierPaillierPublicKey = verifierPaillierSecretKey.publicKey;
    const { pedersen } = verifierPaillierSecretKey.generatePedersen();
    verifierPedersen = pedersen;
  }

  const hasher = Hasher.create().update('test');

  const pub: ZkFacPublic = {
    N: proverPaillierPublicKey.n,
    Aux: verifierPedersen,
  };
  const priv: ZkFacPrivate = {
    P: proverPaillierSecretKey.p,
    Q: proverPaillierSecretKey.q,
  };

  const proof = zkFacCreateProof(priv, pub, hasher.clone());

  const verified = zkFacVerifyProof(proof, pub, hasher.clone());

  assert(verified, 'failed to verify zkFac proof');
});
