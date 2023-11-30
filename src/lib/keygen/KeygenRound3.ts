import { AffinePoint } from "../common.types.js";
import { PartyId } from "../keyConfig.js";
import { PedersenParameters } from "../pedersen.js";
import { Exponent } from "../polynomial/exponent.js";
import { ZkSchCommitment } from "../zk/zksch.js";
import { KeygenInputForRound2 } from "./KeygenRound2.js";

export type KeygenBroadcastForRound3 = {
  from: PartyId,
  RID: bigint,
  C: bigint,
  vssPolynomial: Exponent,
  schnorrCommitment: ZkSchCommitment,
  elGamalPublic: AffinePoint,
  pedersenPublic: PedersenParameters,
  decommitment: Uint8Array,
};

export type KeygenInputForRound3 = {
  inputForRound2: KeygenInputForRound2,
  // TODO ?
};
