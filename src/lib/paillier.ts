// TODO: Add proper comments
// TODO: Implement decryption with randomness
// TODO: Optimize using known values of p and q

import {
  modInv, gcd, abs, modPow, modMultiply,
  randBetween,
} from 'bigint-crypto-utils';

import { sampleUnitModN } from './sample.js';
import { PedersenParams } from './pedersen.js';
import { JSONable } from './serde.js';
import { Hashable, IngestableBasic } from './Hasher.js';

export type PaillierSecretKeyJSON = {
  pHex: string;
  qHex: string;
};

export type PaillierPublicKeyJSON = {
  nHex: string;
};

export class PaillierSecretKey implements JSONable {
  private _p: bigint;
  private _q: bigint;
  private _phi: bigint;
  private _phiInv: bigint;
  public publicKey: PaillierPublicKey;

  private constructor(
    p: bigint,
    q: bigint,
    phi: bigint,
    phiInv: bigint,
    publicKey: PaillierPublicKey,
  ) {
    this._p = p;
    this._q = q;
    this._phi = phi;
    this._phiInv = phiInv;
    this.publicKey = publicKey;
  }

  public get p(): bigint { return this._p; }
  public get q(): bigint { return this._q; }
  public get phi(): bigint { return this._phi; }

  public toJSON(): PaillierSecretKeyJSON {
    return {
      pHex: this._p.toString(16),
      qHex: this._q.toString(16),
    };
  }

  public static fromJSON(secretKeyJson: PaillierSecretKeyJSON): PaillierSecretKey {
    const p = BigInt('0x' + secretKeyJson.pHex);
    const q = BigInt('0x' + secretKeyJson.qHex);
    return PaillierSecretKey.fromPrimes(p, q);
  }

  public static fromPrimes = (p: bigint, q: bigint): PaillierSecretKey => {
    const n = p * q;
    const phi = (p - 1n) * (q - 1n);
    const phiInv = modInv(phi, n);
    const publicKey: PaillierPublicKey = PaillierPublicKey.fromN(n);
    const paillierSecretKey = new PaillierSecretKey(p, q, phi, phiInv, publicKey);
    Object.freeze(paillierSecretKey);
    return paillierSecretKey;
  }

  public decrypt(ciphertext: bigint): bigint {
    if (!this.publicKey.validateCiphertext(ciphertext)) {
      throw new Error('INVALID_CIPHERTEXT');
    }

    const { nSquared } = this.publicKey;

    const c1 = modPow(ciphertext, this._phi, nSquared);
    const c2 = c1 - 1n;
    const c3 = c2 / this.publicKey.n;
    const c4 = modMultiply([c3, this._phiInv], this.publicKey.n);
    const message = modSymmetric(c4, this.publicKey.n);

    return message;
  }

  public generatePedersen(): {
    pedersen: PedersenParams,
    lambda: bigint,
  } {
    const { s, t, lambda } = samplePedersen(this._phi, this.publicKey.n);
    const pedersen = PedersenParams.from(this.publicKey.n, s, t);
    return { pedersen, lambda };
  }
}

export class PaillierPublicKey implements Hashable, JSONable {
  private _n: bigint;
  private _nSquared: bigint;
  private _nPlusOne: bigint;

  private constructor(n: bigint, nSquared: bigint, nPlusOne: bigint) {
    this._n = n;
    this._nSquared = nSquared;
    this._nPlusOne = nPlusOne;
  }

  public get n(): bigint { return this._n; }
  public get nSquared(): bigint { return this._nSquared; }
  public get nPlusOne(): bigint { return this._nPlusOne; }

  public toJSON(): PaillierPublicKeyJSON {
    return {
      nHex: this._n.toString(16),
    };
  }

  public static fromJSON(publicKeyJson: PaillierPublicKeyJSON): PaillierPublicKey {
    const n = BigInt('0x' + publicKeyJson.nHex);
    return PaillierPublicKey.fromN(n);
  }

  public hashable(): Array<IngestableBasic> {
    return [this.n, this.nSquared, this.nPlusOne];
  }

  public static fromN(n: bigint): PaillierPublicKey {
    const nSquared = n * n;
    const nPlusOne = n + 1n;
    const ppk = new PaillierPublicKey(n, nSquared, nPlusOne);
    Object.freeze(ppk);
    return ppk;
  }

  public encryptWithNonce(message: bigint, nonce: bigint): bigint {
    const messageAbs = abs(message);
    const nHalf = this.n / 2n;
    if (messageAbs > nHalf) {
      throw new Error('MESSAGE_TOO_LARGE');
    }

    const c = modPow(this.nPlusOne, message, this.nSquared);
    const rhoN = modPow(nonce, this.n, this.nSquared);
    const ciphertext = modMultiply([c, rhoN], this.nSquared);

    return ciphertext;
  }

  public encrypt(message: bigint): { ciphertext: bigint, nonce: bigint } {
    const nonce = generateRandomNonce(this.n);
    const ciphertext = this.encryptWithNonce(message, nonce);
    return { ciphertext, nonce };
  }

  validateCiphertext = (ciphertext: bigint): boolean => {
    if (!(ciphertext < this.nSquared)) {
      return false;
    }
    if (gcd(ciphertext, this.nSquared) !== 1n) {
      return false;
    };
    return true;
  }
}

const generateRandomNonce = (modulus: bigint): bigint => {
  return sampleUnitModN(modulus);
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
