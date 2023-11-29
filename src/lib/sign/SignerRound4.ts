import { secp256k1 } from "@noble/curves/secp256k1";
import { AffinePoint } from "../common.types.js";
import { isIdentity, scalarFromHash } from "../curve.js";
import { PartyId } from "../keyConfig.js";
import {
  ZkLogstarProof, ZkLogstarPublic, zkLogstarVerifyProof,
} from "../zk/logstar.js";
import { SignInputForRound3 } from "./SignerRound3.js";
import Fn from "../Fn.js";
import { SignBroadcastForRound5, SignInputForRound5 } from "./SignerRound5.js";
import { SignSession } from "./SignSession.js";

export type SignBroadcastForRound4 = {
  from: PartyId;
  DeltaShare: bigint;
  BigDeltaShare: AffinePoint
};

export type SignMessageForRound4 = {
  from: PartyId;
  to: PartyId;

  ProofLog: ZkLogstarProof;
};

export type SignInputForRound4 = {
  DeltaShare: bigint,
  BigDeltaShare: AffinePoint,
  Gamma: AffinePoint,
  ChiShare: bigint,
  inputForRound3: SignInputForRound3,
};

export type SignPartyOutputRound4 = {
  broadcasts: Array<SignBroadcastForRound5>,
  inputForRound5: SignInputForRound5,
};

export class SignerRound4 {
  public session: SignSession;
  private roundInput: SignInputForRound4;

  private DeltaShares: Record<PartyId, bigint> = {};
  private BigDeltaShares: Record<PartyId, AffinePoint> = {};

  constructor(session: SignSession, roundInput: SignInputForRound4) {
    this.roundInput = roundInput;
    this.session = session;
  }

  public handleBroadcastMessage(bmsg: SignBroadcastForRound4): void {
    const point = secp256k1.ProjectivePoint.fromAffine(bmsg.BigDeltaShare);
    if (bmsg.DeltaShare === 0n || isIdentity(point)) {
      throw new Error("Invalid broadcast message");
    }

    this.DeltaShares[bmsg.from] = bmsg.DeltaShare;
    this.BigDeltaShares[bmsg.from] = bmsg.BigDeltaShare;
  }

  public handleDirectMessage(msg: SignMessageForRound4): void {
    const pubData = this.roundInput.inputForRound3.inputForRound2
      .inputForRound1.partiesPublic;
    const pub: ZkLogstarPublic = {
      C: this.roundInput.inputForRound3.K[msg.from],
      X: this.BigDeltaShares[msg.from],
      G: this.roundInput.Gamma,
      prover: pubData[msg.from].paillier,
      aux: pubData[msg.to].pedersen,
    };
    const verified = zkLogstarVerifyProof(
      msg.ProofLog, pub, this.session.cloneHashForId(msg.from),
    );
    if (!verified) {
      throw new Error(`${msg.to}: Invalid log proof from ${msg.from}`);
    }
  }

  public process(): SignPartyOutputRound4 {
    let Delta = 0n;
    let BigDelta = secp256k1.ProjectivePoint.ZERO;
    this.session.partyIds.forEach((partyId) => {
      Delta = Fn.add(Delta, this.DeltaShares[partyId]);
      BigDelta = BigDelta.add(
        secp256k1.ProjectivePoint.fromAffine(this.BigDeltaShares[partyId]),
      );
    });
    const deltaComputed = secp256k1.ProjectivePoint.BASE.multiply(Delta);
    if (!deltaComputed.equals(BigDelta)) {
      throw new Error("computed Delta is inconsistend withBigDelta");
    }

    const deltaInv = Fn.inv(Delta);
    const BigR = secp256k1.ProjectivePoint.fromAffine(this.roundInput.Gamma)
      .multiply(deltaInv);
    const R = BigR.toAffine().x;

    const km = Fn.mul(
      scalarFromHash(
        this.roundInput.inputForRound3.inputForRound2.inputForRound1.message,
      ),
      this.roundInput.inputForRound3.inputForRound2.KShare,
    )

    const sigmaShare = Fn.add(
      Fn.mul(R, this.roundInput.ChiShare),
      km
    );

    const broadcasts: [SignBroadcastForRound5] = [{
      from: this.session.selfId,
      SigmaShare: sigmaShare,
    }];

    this.session.currentRound = 'round5';

    return {
      broadcasts,
      inputForRound5: {
        Delta,
        BigDelta: BigDelta.toAffine(),
        BigR: BigR.toAffine(),
        R,
        inputForRound4: this.roundInput,
      },
    };
  }
};
