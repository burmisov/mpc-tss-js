import { Hasher } from "../Hasher.js";
import { AffinePoint } from "../common.types.js";
import { PartyId } from "../keyConfig.js";
import { PaillierPublicKey, PaillierSecretKey } from "../paillier.js";
import { PedersenParameters } from "../pedersen.js";
import { Exponent } from "../polynomial/exponent.js";
import { ZkSchRandomness } from "../zk/zksch.js";
import { KeygenInputForRound1 } from "./KeygenRound1.js";
import { KeygenBroadcastForRound3, KeygenInputForRound3 } from "./KeygenRound3.js";
import { KeygenSession } from "./KeygenSession.js";

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

export type KeygenRound2Output = {
  broadcasts: Array<KeygenBroadcastForRound3>,
  inputForRound3: KeygenInputForRound3,
};

export class KeygenRound2 {
  private session: KeygenSession;
  private input: KeygenInputForRound2;

  private commitments: Record<PartyId, Uint8Array> = {};

  constructor(session: KeygenSession, input: KeygenInputForRound2) {
    this.session = session;
    this.input = input;
  }

  public handleBroadcastMessage(bmsg: KeygenBroadcastForRound2): void {
    Hasher.validateCommitment(bmsg.commitment);
    this.commitments[bmsg.from] = bmsg.commitment;
  }

  public process(): KeygenRound2Output {
    const broadcasts: Array<KeygenBroadcastForRound3> = [{
      from: this.session.selfId,

      RID: this.input.selfRID,
      C: this.input.chainKey,
      vssPolynomial: this.input.selfVSSpolynomial,
      schnorrCommitment: this.input.schnorrRand.commitment,
      elGamalPublic: this.input.elGamalPublic,
      pedersenPublic: this.input.selfPedersenPublic,
      decommitment: this.input.decommitment,
    }];

    return {
      broadcasts,
      inputForRound3: {
        inputForRound2: this.input,
        commitments: this.commitments,
      },
    };
  }
}
