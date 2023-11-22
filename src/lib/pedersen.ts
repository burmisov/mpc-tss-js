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
