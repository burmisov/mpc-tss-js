// TODO: Create a "short test" path that skips key generation
// TODO: Create a test coverage report
// TODO: Add a proper benchmarking suite

import { describe, it } from "node:test";
import assert from 'node:assert/strict';
import { randBetween } from 'bigint-crypto-utils';

import {
  PaillierPublicKey,
  PaillierSecretKey,
  PaillierSecretKeyJSON,
  paillierAdd,
  paillierMultiply,
} from "./paillier.js";
import {
  randomPaillierPrimes,
  validatePaillierPrime
} from './paillierKeygen.js';

describe("Paillier encryption", async () => {
  const p = 179592502110335963336347735108907147317760904272746519157588428198851642173043932077383231024080457777437444199308940940528740158020956955835017958704625931695110457545843284994471316520797998498062474296013358438785968440081020607611888287234488233606613994066898948321434201732737366068220153564935475802567n;
  const q = 144651337722999591357894368476987413731327694772730408677878934803626218325763401733049627551150267745019646164141178748986827450041894571742897062718616997949877925740444144291875968298065299373438319317040746398994377200405476019627025944607850551945311780131978961657839712750089596117856255513589953855963n;
  await validatePaillierPrime(p);
  await validatePaillierPrime(q);
  const paillierSecretKey = PaillierSecretKey.fromPrimes(p, q);
  const paillierPublicKey = paillierSecretKey.publicKey;

  const encryptDecryptRoundTripTest = (message: bigint) => {
    const { ciphertext } = paillierPublicKey.encrypt(message);
    const messageDecrypted = paillierSecretKey.decrypt(ciphertext);
    assert.equal(
      message, messageDecrypted,
      'Decrypted message does not match original'
    );
  }

  const homomorphicAddTest = (messageA: bigint, messageB: bigint) => {
    const { ciphertext: ciphertextA } = paillierPublicKey.encrypt(messageA);
    const { ciphertext: ciphertextB } = paillierPublicKey.encrypt(messageB);
    const ciphertextSum = paillierAdd(
      paillierPublicKey, ciphertextA, ciphertextB
    );
    const expectedSum = messageA + messageB;
    const decryptedSum = paillierSecretKey.decrypt(ciphertextSum);
    assert.equal(
      expectedSum, decryptedSum,
      'Homomorphic addition failed'
    );
  }

  const homomorphicMultiplyTest = (message: bigint, scalar: bigint) => {
    const { ciphertext } = paillierPublicKey.encrypt(message);
    const ciphertextProduct = paillierMultiply(paillierPublicKey, ciphertext, scalar);
    const expectedProduct = message * scalar;
    const decryptedProduct = paillierSecretKey.decrypt(ciphertextProduct);
    assert.equal(
      expectedProduct, decryptedProduct,
      'Homomorphic multiplication failed'
    );
  }

  it('validates ciphertext', () => {
    assert.throws(
      () => {
        paillierSecretKey.decrypt(0n);
      },
      { message: 'INVALID_CIPHERTEXT' },
      'decrypting 0 should fail',
    );

    assert.throws(
      () => {
        paillierSecretKey.decrypt(paillierPublicKey.n);
      },
      { message: 'INVALID_CIPHERTEXT' },
      'decrypting N should fail',
    );

    assert.throws(
      () => {
        paillierSecretKey.decrypt(paillierPublicKey.n * 2n);
      },
      { message: 'INVALID_CIPHERTEXT' },
      'decrypting 2N should fail',
    );

    assert.throws(
      () => {
        paillierSecretKey.decrypt(paillierPublicKey.n ** 2n);
      },
      { message: 'INVALID_CIPHERTEXT' },
      'decrypting N^2 should fail',
    );
  });

  it('deserializes keys', () => {
    const secretKeySerialized: PaillierSecretKeyJSON = {
      pHex: p.toString(16),
      qHex: q.toString(16),
    };
    const secretKeyDeserialized = PaillierSecretKey.fromJSON(secretKeySerialized);
    assert.equal(
      paillierSecretKey.publicKey.n,
      secretKeyDeserialized.publicKey.n,
      'Deserialized secret key does not match original'
    );

    const publicKeySerialized = {
      nHex: paillierPublicKey.n.toString(16),
    };
    const publicKeyDeserialized = PaillierPublicKey.fromJSON(publicKeySerialized);
    assert.equal(
      paillierPublicKey.n,
      publicKeyDeserialized.n,
      'Deserialized public key does not match original'
    );
  });

  it("encrypts and decrypts", () => {
    for (let i = 0; i < 10; i++) {
      const message = randBetween(2n ** 64n, 1n);
      encryptDecryptRoundTripTest(message);
    }
  });

  it('performs homomorphic addition', () => {
    for (let i = 0; i < 10; i++) {
      const messageA = randBetween(2n ** 64n, 1n);
      const messageB = randBetween(2n ** 64n, 1n);
      homomorphicAddTest(messageA, messageB);
    }
  });

  it('performs homomorphic multiplication', () => {
    for (let i = 0; i < 10; i++) {
      const message = randBetween(2n ** 64n, 1n);
      const scalar = randBetween(2n ** 64n, 1n);
      homomorphicMultiplyTest(message, scalar);
    }
  });

  it('LONG: generates a secret key from random primes', { skip: true }, async () => {
    const { p, q } = await randomPaillierPrimes();
    const secretKey = PaillierSecretKey.fromPrimes(p, q);
    validatePaillierPrime(p);
    validatePaillierPrime(q);
  });
});
