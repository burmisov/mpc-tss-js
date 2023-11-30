import { AffinePoint } from "../common.types.js";
import { PartyId } from "../keyConfig.js";
import { PaillierPublicKey, PaillierSecretKey } from "../paillier.js";
import { PedersenParameters } from "../pedersen.js";
import { Exponent } from "../polynomial/exponent.js";
import { ZkSchRandomness } from "../zk/zksch.js";
import { KeygenInputForRound1 } from "./KeygenRound1.js";

export type KeygenBroadcastForRound2 = {
  from: PartyId,
  commitment: Uint8Array,
};

export type KeygenInputForRound2 = {
  inputRound1: KeygenInputForRound1,
  selfVSSpolynomial: Exponent,
  selfCommitment: Uint8Array,
  selfRID: bigint,
  chainKey: bigint,
  selfShare: bigint,
  elGamalPublic: AffinePoint,
  selfPaillierPublic: PaillierPublicKey,
  selfPedersenPublic: PedersenParameters,
  elGamalSecret: bigint,
  paillierSecret: PaillierSecretKey,
  pedersenSecret: bigint,
  schnorrRand: ZkSchRandomness,
  decommitment: Uint8Array,
};
