import {
  modInv, bitLength, randBitsSync, gcd, abs, modPow, modMultiply
} from 'bigint-crypto-utils';

type PaillierSecretKey = {
  // p, q such that N = p⋅q
  p: bigint;
  q: bigint;

  // phi = ϕ = (p-1)(q-1) cached
  phi: bigint;
  // phiInv = ϕ⁻¹ mod N cached
  phiInv: bigint;

  publicKey: PaillierPublicKey;
}

type PaillierPublicKey = {
  // n = p⋅q
  n: bigint;
  // nSquared = n²
  nSquared: bigint;
  // n + 1 cached
  nPlusOne: bigint;
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
  const maxIterations = 256;
  const randBitLength = Math.floor((bitLength(modulus) + 7) / 8);
  for (let i = 0; i < maxIterations; i++) {
    const nonceBits = randBitsSync(randBitLength);
    const nonce = BigInt('0x' + nonceBits.toString('hex'));
    const isUnit = (gcd(nonce, modulus) === 1n);
    if (isUnit) {
      return nonce;
    }
  }
  throw new Error('MAX_INT_ITERATIONS_EXCEEDED');
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
