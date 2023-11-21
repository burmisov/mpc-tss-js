import { describe, it } from "node:test";
import assert from 'node:assert/strict';

import { randBetween } from 'bigint-crypto-utils';

import {
  paillierSecretKeyFromPrimes,
  paillierEncrypt,
  paillierDecrypt,
  paillierAdd,
  paillierMultiply,
} from "./paillier.js";

describe("paillier", () => {
  const p = BigInt('0xfd90167f42443623d284ea828fb13e374cbf73e16cc6755422b97640ab7fc77fdaf452b4f3a2e8472614eee11cc8eaf48783ce2b4876a3bb72e9acf248e86daa5ce4d5a88e77352bcba30a998cd8b0ad2414d43222e3ba56d82523e2073730f817695b34a4a26128d5e030a7307d3d04456dc512ebb8b53fdbd1dfc07662099b');
  const q = BigInt('0xdb531c32024a262a0df9603e48c79e863f9539a82b8619480289ec38c3664cc63e3ac2c04888827559ffdbcb735a8d2f1d24baf910643ce819452d95caffb686e6110057985e93605de89e33b99c34140ef362117f975a5056bff14a51c9cd16a4961be1f02c081c7ad8b2a5450858023a157afa3c3441e8e00941f8d33ed6b7');
  const paillierSecretKey = paillierSecretKeyFromPrimes(p, q);
  const paillierPublicKey = paillierSecretKey.publicKey;

  const encryptDecryptRoundTripTest = (message: bigint) => {
    const { ciphertext } = paillierEncrypt(
      paillierPublicKey, message,
    );
    const messageDecrypted = paillierDecrypt(paillierSecretKey, ciphertext);
    assert.equal(
      message, messageDecrypted,
      'Decrypted message does not match original'
    );
  }

  const homomorphicAddTest = (messageA: bigint, messageB: bigint) => {
    const { ciphertext: ciphertextA } = paillierEncrypt(
      paillierPublicKey, messageA,
    );
    const { ciphertext: ciphertextB } = paillierEncrypt(
      paillierPublicKey, messageB,
    );
    const ciphertextSum = paillierAdd(
      paillierPublicKey, ciphertextA, ciphertextB
    );
    const expectedSum = messageA + messageB;
    const decryptedSum = paillierDecrypt(
      paillierSecretKey, ciphertextSum
    );
    assert.equal(
      expectedSum, decryptedSum,
      'Homomorphic addition failed'
    );
  }

  const homomorphicMultiplyTest = (message: bigint, scalar: bigint) => {
    const { ciphertext } = paillierEncrypt(
      paillierPublicKey, message,
    );
    const ciphertextProduct = paillierMultiply(paillierPublicKey, ciphertext, scalar);
    const expectedProduct = message * scalar;
    const decryptedProduct = paillierDecrypt(paillierSecretKey, ciphertextProduct);
    assert.equal(
      expectedProduct, decryptedProduct,
      'Homomorphic multiplication failed'
    );
  }

  it('should validate ciphertext', () => {
    assert.throws(
      () => {
        paillierDecrypt(paillierSecretKey, 0n);
      },
      { message: 'INVALID_CIPHERTEXT' },
      'decrypting 0 should fail',
    );

    assert.throws(
      () => {
        paillierDecrypt(paillierSecretKey, paillierPublicKey.n);
      },
      { message: 'INVALID_CIPHERTEXT' },
      'decrypting N should fail',
    );

    assert.throws(
      () => {
        paillierDecrypt(paillierSecretKey, paillierPublicKey.n * 2n);
      },
      { message: 'INVALID_CIPHERTEXT' },
      'decrypting 2N should fail',
    );

    assert.throws(
      () => {
        paillierDecrypt(paillierSecretKey, paillierPublicKey.n ** 2n);
      },
      { message: 'INVALID_CIPHERTEXT' },
      'decrypting N^2 should fail',
    );
  });

  it("should encrypt and decrypt", () => {
    for (let i = 0; i < 10; i++) {
      const message = randBetween(2n ** 64n, 1n);
      encryptDecryptRoundTripTest(message);
    }
  });

  it('should perform homomorphic addition', () => {
    for (let i = 0; i < 10; i++) {
      const messageA = randBetween(2n ** 64n, 1n);
      const messageB = randBetween(2n ** 64n, 1n);
      homomorphicAddTest(messageA, messageB);
    }
  });

  it('should perform homomorphic multiplication', () => {
    for (let i = 0; i < 10; i++) {
      const message = randBetween(2n ** 64n, 1n);
      const scalar = randBetween(2n ** 64n, 1n);
      homomorphicMultiplyTest(message, scalar);
    }
  });
});
