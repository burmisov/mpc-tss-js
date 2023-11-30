import { beforeEach, describe, it, test } from "node:test";
import assert from 'assert/strict';
import { Hasher } from "./Hasher.js";
import { AffinePoint } from "./common.types.js";
import { secp256k1 } from "@noble/curves/secp256k1";
import { paillierGeneratePedersen, paillierSecretKeyFromPrimes } from "./paillier.js";

describe('Hasher', () => {
  const p = 179592502110335963336347735108907147317760904272746519157588428198851642173043932077383231024080457777437444199308940940528740158020956955835017958704625931695110457545843284994471316520797998498062474296013358438785968440081020607611888287234488233606613994066898948321434201732737366068220153564935475802567n;
  const q = 144651337722999591357894368476987413731327694772730408677878934803626218325763401733049627551150267745019646164141178748986827450041894571742897062718616997949877925740444144291875968298065299373438319317040746398994377200405476019627025944607850551945311780131978961657839712750089596117856255513589953855963n;
  const paillierSecretKey = paillierSecretKeyFromPrimes(p, q);

  let hasher: Hasher;

  beforeEach(() => {
    hasher = new Hasher();
  });

  it('hashes a string', () => {
    const data: string = 'hello world';
    const hash = hasher.update(data).digestBytes();
    assert.equal(hash.length, 32);
  });

  it('supports bigint', () => {
    const data: string = 'hello world';
    const hash = hasher.update(data).digestBigint();
    assert.equal(typeof hash, 'bigint');
  });

  it('hashes a Uint8Array', () => {
    const data = new Uint8Array([1, 2, 3, 4, 5]);
    const hash = hasher.update(data).digestBigint();
    const originalHash = new Hasher().update(data).digestBigint();
    assert.equal(hash, originalHash);
  });

  it('prevents reuse', () => {
    const data: string = 'hello world';
    hasher.update(data).digestBytes();
    assert.throws(() => {
      hasher.digestBytes();
    });
    assert.throws(() => {
      hasher.update('foo');
    });
  });

  it('hashes an AffinePoint', () => {
    const data: AffinePoint = {
      x: 1n,
      y: 2n,
    };
    const hash = hasher.update(data).digestBigint();
    const originalHash = new Hasher().update(data.x).update(data.y).digestBigint();
    assert.equal(hash, originalHash);
  });

  it('hashes a ProjectivePoint', () => {
    const data = secp256k1.ProjectivePoint.BASE;
    const hash = hasher.update(data).digestBigint();
    const originalHash = new Hasher().update(data.toRawBytes()).digestBigint();
    assert.equal(hash, originalHash);
  });

  it('hashes multiple things', () => {
    const data = [
      'hello world',
      1n,
      new Uint8Array([1, 2, 3, 4, 5]),
      secp256k1.ProjectivePoint.BASE,
    ];
    const hash = hasher.updateMulti(data).digestBigint();
    const originalHash = new Hasher()
      .update(data[0])
      .update(data[1])
      .update(data[2])
      .update(secp256k1.ProjectivePoint.BASE.toRawBytes())
      .digestBigint();
    assert.equal(hash, originalHash);
  });

  it('hashes a Paillier public key', () => {
    const paillierPublicKey = paillierSecretKey.publicKey;

    const hash = hasher.update(paillierPublicKey).digestBigint();
    const originalHash = new Hasher()
      .update(paillierPublicKey.n)
      .update(paillierPublicKey.nSquared)
      .update(paillierPublicKey.nPlusOne)
      .digestBigint();
    assert.equal(hash, originalHash);
  });

  it('hashes Pedersen parameters', () => {
    const { pedersen } = paillierGeneratePedersen(paillierSecretKey);
    const hash = hasher.update(pedersen).digestBigint();
    const originalHash = new Hasher()
      .update(pedersen.n)
      .update(pedersen.s)
      .update(pedersen.t)
      .digestBigint();
    assert.equal(hash, originalHash);
  });

  test('commitment/decommitment', () => {
    const data = [
      'hello world',
      1n,
      new Uint8Array([1, 2, 3, 4, 5]),
      secp256k1.ProjectivePoint.BASE,
    ];
    const { commitment, decommitment } = hasher.commit(data);
    const verified = hasher.decommit(commitment, decommitment, data);
    assert.equal(verified, true);
    const nonVerified = hasher.decommit(commitment, decommitment, ['foo']);
    assert.equal(nonVerified, false);
  });
});
