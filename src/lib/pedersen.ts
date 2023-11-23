import { gcd, modPow, modMultiply } from "bigint-crypto-utils";

// TODO: add tests but first add testable functions
// currently it seems untestable because it is unclear where
// the arguments for Verify should come from
// I suppose it is going to become more clear once we have ZK proofs in place

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

export const pedersenCommit = (
  parameters: PedersenParameters,
  x: bigint,
  y: bigint,
): bigint => {
  const sx = modPow(parameters.s, x, parameters.n);
  const ty = modPow(parameters.t, y, parameters.n);
  return modMultiply([sx, ty], parameters.n);
};

export const pedersenVerify = (
  parameters: PedersenParameters,
  a: bigint, b: bigint, e: bigint,
  S: bigint, T: bigint,
): boolean => {
  try {
    pedersenValidateParameters({ n: parameters.n, s: S, t: T });
  } catch (error) {
    // TODO: check error type
    return false;
  }

  const sa = modPow(parameters.s, a, parameters.n);
  const tb = modPow(parameters.t, b, parameters.n);
  const lhs = modMultiply([sa, tb], parameters.n);

  const te = modPow(T, e, parameters.n);
  const rhs = modMultiply([te, S], parameters.n);

  return lhs === rhs;
}
