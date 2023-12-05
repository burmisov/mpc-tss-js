import { bitLength, isProbablyPrime, randBytesSync } from "bigint-crypto-utils";

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
    if (sieve[p] === 0) { continue; }
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
};
const PRIMES = primes(PRIME_BOUND);
const tryBlumPrime = async (): Promise<bigint | null> => {
  const randomByteLength = Math.floor((BITS_BLUM_PRIME + 7) / 8);
  const bytes = randBytesSync(randomByteLength);

  bytes[bytes.length - 1] |= 3;
  bytes[0] |= 192;

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
    for (let i = Number(firstMultiple); i < sieve.length; i += Number(prime)) {
      sieve[i] = 0;
      sieve[i + 1] = 0;
    }
  }

  let p: bigint | undefined = undefined;
  let q = 0n;
  for (let delta = 0; delta < sieve.length; delta += 1) {
    if (sieve[delta] === 0) { continue; }
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
};

export const randomPaillierPrimes = async (): Promise<{ p: bigint; q: bigint; }> => {
  let p: bigint | undefined = undefined;
  let q: bigint;

  while (true) {
    let x = await tryBlumPrime();

    if (x === null) { continue; }

    if (p === undefined) {
      p = x;
    } else {
      q = x;
      return { p, q };
    }
  }
};

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
};

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
