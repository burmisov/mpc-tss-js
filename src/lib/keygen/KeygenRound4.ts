import { PartyId } from "../keyConfig.js";
import { ZkFacProof } from "../zk/fac.js";
import { ZkModProof } from "../zk/mod.js";
import { ZkPrmProof } from "../zk/prm.js";
import { KeygenInputForRound3 } from "./KeygenRound3.js";

export type KeygenBroadcastForRound4 = {
  from: PartyId,
  modProof: ZkModProof,
  prmProof: ZkPrmProof,
};

export type KeygenDirectMessageForRound4 = {
  from: PartyId,
  to: PartyId,
  share: bigint,
  facProof: ZkFacProof,
};

export type KeygenInputForRound4 = {
  inputForRound3: KeygenInputForRound3,
  RID: bigint,
  ChainKey: bigint,
};
