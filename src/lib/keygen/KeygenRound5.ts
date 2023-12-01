import { PartyId, PartySecretKeyConfig } from "../keyConfig.js";
import { ZkSchResponse } from "../zk/zksch.js";
import { KeygenInputForRound4 } from "./KeygenRound4.js";

export type KeygenBroadcastForRound5 = {
  from: PartyId,
  SchnorrResponse: ZkSchResponse,
};

export type KeygenInputForRound5 = {
  inputForRound4: KeygenInputForRound4,
  UpdatedConfig: PartySecretKeyConfig,
};

// TODO
