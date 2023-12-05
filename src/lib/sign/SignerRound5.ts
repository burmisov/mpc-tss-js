import Fn from "../Fn.js";
import { AffinePoint } from "../common.types.js";
import { PartyId } from "../keyConfig.js";
import { SignInputForRound4 } from "./SignerRound4.js";
import { verifySignature } from "../curve.js";
import { SignSession } from "./SignSession.js";

export type SignBroadcastForRound5JSON = {
  from: string,
  SigmaShareHex: string,
};

export class SignBroadcastForRound5 {
  public readonly from: PartyId;
  public readonly SigmaShare: bigint;

  private constructor(from: PartyId, SigmaShare: bigint) {
    this.from = from;
    this.SigmaShare = SigmaShare;
  }

  public static from({
    from,
    SigmaShare,
  }: {
    from: PartyId,
    SigmaShare: bigint,
  }): SignBroadcastForRound5 {
    const bmsg = new SignBroadcastForRound5(from, SigmaShare);
    Object.freeze(bmsg);
    return bmsg;
  }

  public static fromJSON({
    from,
    SigmaShareHex,
  }: SignBroadcastForRound5JSON): SignBroadcastForRound5 {
    const SigmaShare = BigInt(`0x${SigmaShareHex}`);
    const bmsg = new SignBroadcastForRound5(from, SigmaShare);
    Object.freeze(bmsg);
    return bmsg;
  }

  public toJSON(): SignBroadcastForRound5JSON {
    return {
      from: this.from,
      SigmaShareHex: this.SigmaShare.toString(16),
    };
  }
};

export type SignInputForRound5 = {
  Delta: bigint,
  BigDelta: AffinePoint,
  BigR: AffinePoint,
  R: bigint,
  inputForRound4: SignInputForRound4,
};

export type SignPartyOutputRound5 = {
  signature: {
    R: AffinePoint,
    S: bigint,
  },
};

export class SignerRound5 {
  public session: SignSession;
  private roundInput: SignInputForRound5;

  private SigmaShares: Record<PartyId, bigint> = {};

  constructor(session: SignSession, roundInput: SignInputForRound5) {
    this.roundInput = roundInput;
    this.session = session;
  }

  public handleBroadcastMessage(bmsg: SignBroadcastForRound5): void {
    if (bmsg.SigmaShare === 0n) {
      throw new Error(`SigmaShare from ${bmsg.from} is zero`);
    }
    this.SigmaShares[bmsg.from] = bmsg.SigmaShare;
  }

  public process(): SignPartyOutputRound5 {
    let Sigma = 0n;
    this.session.partyIds.forEach((partyId) => {
      Sigma = Fn.add(Sigma, this.SigmaShares[partyId]);
    });

    const signature = {
      R: this.roundInput.BigR,
      S: Sigma,
    };

    const { publicKey, message } = this.roundInput.inputForRound4.inputForRound3.
      inputForRound2.inputForRound1;

    const verified = verifySignature(
      signature.R,
      signature.S,
      publicKey,
      message
    );

    if (!verified) {
      throw new Error("Signature verification failed");
    }

    return {
      signature,
    };
  }
}
