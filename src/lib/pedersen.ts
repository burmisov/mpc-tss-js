import { gcd } from "bigint-crypto-utils";

export type PedersenParameters = {
  n: bigint;
  s: bigint;
  t: bigint;
};

export type PedersenParametersSerialized = {
  nHex: string;
  sHex: string;
  tHex: string;
};

export const pedersenParametersFromSerialized = (
  parametersSerialized: PedersenParametersSerialized
): PedersenParameters => {
  const n = BigInt('0x' + parametersSerialized.nHex);
  const s = BigInt('0x' + parametersSerialized.sHex);
  const t = BigInt('0x' + parametersSerialized.tHex);
  return { n, s, t };
}

export const pedersenValidateParameters = (
  parameters: PedersenParameters
) => {
  const { n, s, t } = parameters;
  if (n <= 0n) {
    throw new Error('INVALID_PEDERSEN_PARAMETERS: n must be positive');
  }
  if (s <= 0n) {
    throw new Error('INVALID_PEDERSEN_PARAMETERS: s must be positive');
  }
  if (t <= 0n) {
    throw new Error('INVALID_PEDERSEN_PARAMETERS: t must be positive');
  }
  if (s >= n) {
    throw new Error('INVALID_PEDERSEN_PARAMETERS: s must be less than n');
  }
  if (t >= n) {
    throw new Error('INVALID_PEDERSEN_PARAMETERS: t must be less than n');
  }
  if (s === t) {
    throw new Error('INVALID_PEDERSEN_PARAMETERS: s and t must be different');
  }
  if (gcd(s, n) !== 1n) {
    throw new Error('INVALID_PEDERSEN_PARAMETERS: s must be coprime to n');
  }
  if (gcd(t, n) !== 1n) {
    throw new Error('INVALID_PEDERSEN_PARAMETERS: t must be coprime to n');
  }
}
