import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { Hasher } from "../Hasher.js";
import { AffinePoint } from "../common.types.js";
import { PartyId } from "../keyConfig.js";
import { PaillierPublicKey, PaillierSecretKey } from "../paillier.js";
import { PedersenParams } from "../pedersen.js";
import { Exponent } from "../polynomial/exponent.js";
import { JSONable } from "../serde.js";
import { ZkSchRandomness } from "../zk/zksch.js";
import { KeygenInputForRound1 } from "./KeygenRound1.js";
import { KeygenBroadcastForRound3, KeygenInputForRound3 } from "./KeygenRound3.js";
import { KeygenSession } from "./KeygenSession.js";

type KeygenBroadcastForRound2JSON = {
  from: string,
  commitmentHex: string,
};

export class KeygenBroadcastForRound2 implements JSONable {
  public readonly from: PartyId;
  public readonly commitment: Uint8Array;

  private constructor(from: PartyId, commitment: Uint8Array) {
    this.from = from;
    this.commitment = commitment;
  }

  public static from(
    { from, commitment }: { from: PartyId, commitment: Uint8Array }
  ): KeygenBroadcastForRound2 {
    const b = new KeygenBroadcastForRound2(from, commitment);
    Object.freeze(b);
    return b;
  }

  public toJSON(): KeygenBroadcastForRound2JSON {
    return {
      from: this.from,
      commitmentHex: bytesToHex(this.commitment),
    };
  }

  public static fromJSON(json: KeygenBroadcastForRound2JSON): KeygenBroadcastForRound2 {
    const commitment = hexToBytes(json.commitmentHex);
    return new KeygenBroadcastForRound2(json.from, commitment);
  }
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
  selfPedersenPublic: PedersenParams,
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
    const broadcasts: Array<KeygenBroadcastForRound3> = [
      KeygenBroadcastForRound3.from({
        from: this.session.selfId,
        RID: this.input.selfRID,
        C: this.input.chainKey,
        vssPolynomial: this.input.selfVSSpolynomial,
        schnorrCommitment: this.input.schnorrRand.commitment,
        elGamalPublic: this.input.elGamalPublic,
        pedersenPublic: this.input.selfPedersenPublic,
        decommitment: this.input.decommitment,
      }),
    ];

    return {
      broadcasts,
      inputForRound3: {
        inputForRound2: this.input,
        commitments: this.commitments,
      },
    };
  }
}
