import { AffinePoint } from "../common.types.js";
import { PartyId } from "../keyConfig.js";
import { ZkAffgProof } from "../zk/affg.js";
import { ZkLogstarProof } from "../zk/logstar.js";

export type SignBroadcastForRound3 = {
  from: PartyId;
  BigGammaShare: AffinePoint
};

export type SignMessageForRound3 = {
  from: PartyId;
  to: PartyId;

  DeltaD: bigint; // Ciphertext
  DeltaF: bigint; // Ciphertext
  DeltaProof: ZkAffgProof;
  ChiD: bigint; // Ciphertext
  ChiF: bigint; // Ciphertext
  ChiProof: ZkAffgProof;
  ProofLog: ZkLogstarProof;
};

export type SignInputForRound3 = {
  DeltaShareBetas: Record<PartyId, bigint>;
  ChiShareBetas: Record<PartyId, bigint>;
};
