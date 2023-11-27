import Fn from "../Fn.js";
import { AffinePoint } from "../common.types.js";
import { PartyId } from "../keyConfig.js";
import { SignInputForRound4 } from "./SignerRound4.js";
import { SignPartySession } from "./sign.js";
import { verifySignature } from "../curve.js";

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

export type SignPartyOutputRound5 = {
  signature: {
    R: AffinePoint,
    S: bigint,
  },
};

export class SignerRound5 {
  public session: SignPartySession;
  private roundInput: SignInputForRound5;

  private SigmaShares: Record<PartyId, bigint> = {};

  constructor(session: SignPartySession, roundInput: SignInputForRound5) {
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
