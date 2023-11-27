import { AffinePoint } from "../common.types.js";
import { PartyId } from "../keyConfig.js";
import { ZkLogstarProof } from "../zk/logstar.js";
import { SignInputForRound3 } from "./SignerRound3.js";

export type SignBroadcastForRound4 = {
  from: PartyId;
  DeltaShare: bigint;
  BigDeltaShare: AffinePoint
};

export type SignMessageForRound4 = {
  from: PartyId;
  to: PartyId;

  ProofLog: ZkLogstarProof;
};

export type SignInputForRound4 = {
  DeltaShare: bigint,
  BigDeltaShare: AffinePoint,
  Gamma: AffinePoint,
  ChiShare: bigint,
  inputForRound3: SignInputForRound3,
};
