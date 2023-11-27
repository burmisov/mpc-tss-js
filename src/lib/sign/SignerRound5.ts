import { AffinePoint } from "../common.types.js";
import { PartyId } from "../keyConfig.js";
import { SignInputForRound4 } from "./SignerRound4.js";

export type SignBroadcastForRound5 = {
  from: PartyId,
  SigmaShare: bigint,
};

export type SignInputForRound5 = {
  Delta: bigint,
  BigDelta: AffinePoint,
  BigR: AffinePoint,
  R: bigint,
  inputForRound4: SignInputForRound4,
};
