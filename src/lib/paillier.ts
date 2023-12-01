// TODO: Add proper comments
// TODO: Implement decryption with randomness
// TODO: Optimize using known values of p and q

import {
  modInv, bitLength, gcd, abs, modPow, modMultiply,
  isProbablyPrime, randBytesSync, phi, randBetween,
} from 'bigint-crypto-utils';

import { sampleUnitModN } from './sample.js';
import { PedersenParameters } from './pedersen.js';

export type PaillierSecretKey = {
  p: bigint;
  q: bigint;
  phi: bigint;
  phiInv: bigint;
  publicKey: PaillierPublicKey;
}

export type PaillierPublicKey = {
  n: bigint;
  nSquared: bigint;
  nPlusOne: bigint;
}

export type PaillierSecretKeySerialized = {
  pHex: string;
  qHex: string;
};

export type PaillierPublicKeySerialized = {
  nHex: string;
};

export const paillierSecretKeyFromSerialized = (
  secretKeySerialized: PaillierSecretKeySerialized
): PaillierSecretKey => {
  const p = BigInt('0x' + secretKeySerialized.pHex);
  const q = BigInt('0x' + secretKeySerialized.qHex);
  return paillierSecretKeyFromPrimes(p, q);
}

export const paillierPublicKeyFromN = (n: bigint): PaillierPublicKey => {
  const nSquared = n * n;
  const nPlusOne = n + 1n;
  return { n, nSquared, nPlusOne };
};

export const paillierPublicKeyFromSerialized = (
  publicKeySerialized: PaillierPublicKeySerialized
): PaillierPublicKey => {
  const n = BigInt('0x' + publicKeySerialized.nHex);
  return paillierPublicKeyFromN(n);
}

export const paillierSecretKeyFromPrimes = (p: bigint, q: bigint): PaillierSecretKey => {
  const n = p * q;
  const nSquared = n * n;
  const nPlusOne = n + 1n;
  const phi = (p - 1n) * (q - 1n);
  const phiInv = modInv(phi, n);
  const publicKey: PaillierPublicKey = { n, nSquared, nPlusOne };
  const paillierSecretKey: PaillierSecretKey = { p, q, phi, phiInv, publicKey };
  return paillierSecretKey;
}

export const generateRandomNonce = (modulus: bigint): bigint => {
  return sampleUnitModN(modulus);
}

export const paillierEncrypt = (
  publicKey: PaillierPublicKey,
  message: bigint
): { ciphertext: bigint, nonce: bigint } => {
  const nonce = generateRandomNonce(publicKey.n);
  const ciphertext = paillierEncryptWithNonce(
    publicKey, message, nonce
  );
  return { ciphertext, nonce };
}

export const paillierEncryptWithNonce = (
  publicKey: PaillierPublicKey,
  message: bigint,
  nonce: bigint,
): bigint => {
  const messageAbs = abs(message);
  const nHalf = publicKey.n / 2n;
  if (messageAbs > nHalf) {
    throw new Error('MESSAGE_TOO_LARGE');
  }

  const c = modPow(publicKey.nPlusOne, message, publicKey.nSquared);
  const rhoN = modPow(nonce, publicKey.n, publicKey.nSquared);
  const ciphertext = modMultiply([c, rhoN], publicKey.nSquared);

  return ciphertext;
}

export const validateCiphertext = (
  publicKey: PaillierPublicKey,
  ciphertext: bigint
): boolean => {
  if (!(ciphertext < publicKey.nSquared)) {
    return false;
  }
  if (gcd(ciphertext, publicKey.nSquared) !== 1n) {
    return false;
  };
  return true;
}

const modSymmetric = (x: bigint, n: bigint): bigint => {
  const absMod = (abs(x) as bigint) % n;
  const negated = modMultiply([-absMod], n);
  if (negated <= absMod) {
    return -negated;
  } else {
    return absMod;
  }
}

export const paillierDecrypt = (
  secretKey: PaillierSecretKey,
  ciphertext: bigint,
): bigint => {
  if (!validateCiphertext(secretKey.publicKey, ciphertext)) {
    throw new Error('INVALID_CIPHERTEXT');
  }

  const { nSquared } = secretKey.publicKey;

  const c1 = modPow(ciphertext, secretKey.phi, nSquared);
  const c2 = c1 - 1n;
  const c3 = c2 / secretKey.publicKey.n;
  const c4 = modMultiply([c3, secretKey.phiInv], secretKey.publicKey.n);
  const message = modSymmetric(c4, secretKey.publicKey.n);

  return message;
}

export const paillierAdd = (
  publicKey: PaillierPublicKey,
  ciphertextA: bigint,
  ciphertextB: bigint,
): bigint => {
  const ciphertextSum = modMultiply(
    [ciphertextA, ciphertextB], publicKey.nSquared
  );
  return ciphertextSum;
}

export const paillierMultiply = (
  publicKey: PaillierPublicKey,
  ciphertext: bigint,
  scalar: bigint,
): bigint => {
  const ciphertextProduct = modPow(
    ciphertext, scalar, publicKey.nSquared
  );
  return ciphertextProduct;
}

export const paillierGeneratePedersen = (
  secretKey: PaillierSecretKey,
): {
  pedersen: PedersenParameters,
  lambda: bigint,
} => {
  const { s, t, lambda } = samplePedersen(secretKey.phi, secretKey.publicKey.n);
  const pedersen: PedersenParameters = {
    n: secretKey.publicKey.n,
    s, t,
  };
  return { pedersen, lambda };
}

const samplePedersen = (phi: bigint, n: bigint): {
  s: bigint,
  t: bigint,
  lambda: bigint,
} => {
  const lambda = randBetween(phi);
  const tau = sampleUnitModN(n);
  const t = modMultiply([tau, tau], n);
  const s = modPow(t, lambda, n);
  return { s, t, lambda };
}

const SEC_PARAM = 256;
const BITS_BLUM_PRIME = 4 * SEC_PARAM;
const BITS_PAILLIER = 2 * BITS_BLUM_PRIME;
const SIEVE_SIZE = 2 ** 18;
const PRIME_BOUND = 2 ** 20;
const BLUM_PRIMALITY_ITERATIONS = 20;

const primes = (below: number): bigint[] => {
  const sieve = new Uint8Array(below).fill(1);
  sieve[0] = 0; sieve[1] = 0;
  for (let p = 2; p * p < sieve.length; p++) {
    if (sieve[p] === 0) { continue }
    for (let i = p * 2; i < sieve.length; i += p) {
      sieve[i] = 0;
    }
  }
  const result = [];
  for (let p = 3; p < below; p += 1) {
    if (sieve[p] === 1) {
      result.push(BigInt(p));
    }
  }
  return result;
}

const PRIMES = primes(PRIME_BOUND);

const tryBlumPrime = async (): Promise<bigint | null> => {
  const randomByteLength = Math.floor((BITS_BLUM_PRIME + 7) / 8);
  const bytes = randBytesSync(randomByteLength);

  bytes[bytes.length - 1] |= 3;
  bytes[0] |= 0xC0;

  const base = BigInt('0x' + bytes.toString('hex'));

  const sieve = new Uint8Array(SIEVE_SIZE).fill(1);

  // Remove candidates that are not 3 mod 4
  for (let i = 1; i + 2 < sieve.length; i += 4) {
    sieve[i] = 0;
    sieve[i + 1] = 0;
    sieve[i + 2] = 0;
  }

  let remainder = 0n;
  for (let p = 0; p < PRIMES.length; p += 1) {
    const prime = PRIMES[p];
    remainder = prime;
    remainder = base % remainder;
    let firstMultiple = prime - remainder;
    if (remainder === 0n) {
      firstMultiple = 0n;
    }
    for (
      let i = Number(firstMultiple);
      i < sieve.length;
      i += Number(prime)
    ) {
      sieve[i] = 0;
      sieve[i + 1] = 0;
    }
  }

  let p: bigint | undefined = undefined;
  let q = 0n;
  for (let delta = 0; delta < sieve.length; delta += 1) {
    if (sieve[delta] === 0) { continue }
    p = BigInt(delta);
    p = p + base;
    if (bitLength(p) > BITS_BLUM_PRIME) {
      return null;
    }
    q = (p - 1n) / 2n;
    if (!(await isProbablyPrime(q, BLUM_PRIMALITY_ITERATIONS))) {
      continue;
    }
    if (!(await isProbablyPrime(p, 1))) {
      continue;
    }
    return p;
  }

  return null;
}

export const randomPaillierPrimes = async (): Promise<{ p: bigint, q: bigint }> => {
  let p: bigint | undefined = undefined;
  let q: bigint;

  while (true) {
    let x = await tryBlumPrime();

    if (x === null) { continue }

    if (p === undefined) {
      p = x;
    } else {
      q = x;
      return { p, q };
    }
  }
}

export const validatePaillierPrime = async (p: bigint): Promise<void> => {
  const primeBitLength = bitLength(p);
  if (primeBitLength !== BITS_BLUM_PRIME) {
    throw new Error(`INVALID_P_BITS: ${primeBitLength} !== ${BITS_BLUM_PRIME}`);
  }
  if (p % 4n !== 3n) {
    throw new Error(`INVALID_P_MOD_4: ${p} % 4 !== 3`);
  }
  const pMinus1div2 = (p - 1n) / 2n;
  const isPrime = await isProbablyPrime(pMinus1div2, 1);
  if (!isPrime) {
    throw new Error(`INVALID_P_MINUS_1_DIV_2: ${pMinus1div2} is not prime`);
  }
}

export const paillierValidateN = (n: bigint) => {
  if (!n) { throw new Error('N_IS_NULL'); }

  const bits = bitLength(n);
  if (bits !== BITS_PAILLIER) {
    throw new Error(`INVALID_N_BITS: ${bits} !== ${BITS_PAILLIER}`);
  }

  if (n % 2n === 0n) {
    throw new Error(`INVALID_N_EVEN: ${n} is even`);
  }
};
