export type ZkEncProof = {
  commitment: ZkEncCommitment,
  Z1: bigint,
  Z2: bigint,
  Z3: bigint,
};

export type ZkEncCommitment = {
  S: bigint,
  A: bigint, // Paillier ciphertext
  C: bigint,
};
