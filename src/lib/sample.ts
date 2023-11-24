import {
  bitLength, gcd, randBytesSync,
} from 'bigint-crypto-utils';


export const sampleUnitModN = (modulus: bigint): bigint => {
  const maxIterations = 256;
  const randByteLength = Math.floor((bitLength(modulus) + 7) / 8);
  for (let i = 0; i < maxIterations; i++) {
    const nonceBits = randBytesSync(randByteLength);
    const nonce = BigInt('0x' + nonceBits.toString('hex'));
    const isUnit = (gcd(nonce, modulus) === 1n);
    if (isUnit) {
      return nonce;
    }
  }
  throw new Error('MAX_INT_ITERATIONS_EXCEEDED');
}
