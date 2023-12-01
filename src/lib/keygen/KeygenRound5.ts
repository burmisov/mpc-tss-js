import { PartyId, PartySecretKeyConfig } from "../keyConfig.js";
import {
  ZkSchResponse, zkSchIsResponseValid, zkSchVerifyResponse,
} from "../zk/zksch.js";
import { KeygenInputForRound4 } from "./KeygenRound4.js";
import { KeygenSession } from "./KeygenSession.js";

export type KeygenBroadcastForRound5 = {
  from: PartyId,
  SchnorrResponse: ZkSchResponse,
};

export type KeygenInputForRound5 = {
  inputForRound4: KeygenInputForRound4,
  UpdatedConfig: PartySecretKeyConfig,
};

export type KeygenRound5Output = {
  UpdatedConfig: PartySecretKeyConfig,
};

export class KeygenRound5 {
  constructor(
    private session: KeygenSession,
    private input: KeygenInputForRound5,
  ) { }

  public handleBroadcastMessage(bmsg: KeygenBroadcastForRound5) {
    const { from, SchnorrResponse } = bmsg;

    if (!zkSchIsResponseValid(SchnorrResponse)) {
      throw new Error(`invalid schnorr response from ${from}`);
    }

    const verified = zkSchVerifyResponse(
      SchnorrResponse,
      this.session.cloneHashForId(from),
      this.input.UpdatedConfig.publicPartyData[from].ecdsa,
      this.input.inputForRound4.SchnorrCommitments[from],
    );
    if (!verified) {
      throw new Error(`failed to validate schnorr response from ${from}`);
    }
  }

  process(): KeygenRound5Output {
    return {
      UpdatedConfig: this.input.UpdatedConfig,
    };
  }
}
