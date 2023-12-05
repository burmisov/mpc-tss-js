import { secp256k1 } from "@noble/curves/secp256k1";
import { AffinePoint, AffinePointJSON } from "../common.types.js";
import {
  isIdentity, pointFromJSON, pointToJSON, scalarFromHash,
} from "../curve.js";
import { PartyId } from "../keyConfig.js";
import {
  ZkLogstarProof, ZkLogstarProofJSON, ZkLogstarPublic, zkLogstarVerifyProof,
} from "../zk/logstar.js";
import { SignInputForRound3 } from "./SignerRound3.js";
import Fn from "../Fn.js";
import { SignBroadcastForRound5, SignInputForRound5 } from "./SignerRound5.js";
import { SignSession } from "./SignSession.js";

export type SignBroadcastForRound4JSON = {
  from: string,
  DeltaShareHex: string,
  BigDeltaShare: AffinePointJSON,
};

export class SignBroadcastForRound4 {
  public readonly from: PartyId;
  public readonly DeltaShare: bigint;
  public readonly BigDeltaShare: AffinePoint;

  private constructor(
    from: PartyId, DeltaShare: bigint, BigDeltaShare: AffinePoint,
  ) {
    this.from = from;
    this.DeltaShare = DeltaShare;
    this.BigDeltaShare = BigDeltaShare;
  }

  public static from({
    from,
    DeltaShare,
    BigDeltaShare,
  }: {
    from: PartyId,
    DeltaShare: bigint,
    BigDeltaShare: AffinePoint,
  }): SignBroadcastForRound4 {
    const bmsg = new SignBroadcastForRound4(from, DeltaShare, BigDeltaShare);
    Object.freeze(bmsg);
    return bmsg;
  }

  public static fromJSON({
    from,
    DeltaShareHex,
    BigDeltaShare,
  }: SignBroadcastForRound4JSON): SignBroadcastForRound4 {
    const DeltaShare = BigInt(`0x${DeltaShareHex}`);
    const bmsg = new SignBroadcastForRound4(
      from, DeltaShare, pointFromJSON(BigDeltaShare),
    );
    Object.freeze(bmsg);
    return bmsg;
  }

  public toJSON(): SignBroadcastForRound4JSON {
    return {
      from: this.from,
      DeltaShareHex: this.DeltaShare.toString(16),
      BigDeltaShare: pointToJSON(this.BigDeltaShare),
    };
  }
};

export type SignMessageForRound4JSON = {
  from: string,
  to: string,
  ProofLog: ZkLogstarProofJSON,
};

export class SignMessageForRound4 {
  public readonly from: PartyId;
  public readonly to: PartyId;
  public readonly ProofLog: ZkLogstarProof;

  private constructor(
    from: PartyId, to: PartyId, ProofLog: ZkLogstarProof,
  ) {
    this.from = from;
    this.to = to;
    this.ProofLog = ProofLog;
  }

  public static from({
    from,
    to,
    ProofLog,
  }: {
    from: PartyId,
    to: PartyId,
    ProofLog: ZkLogstarProof,
  }): SignMessageForRound4 {
    const msg = new SignMessageForRound4(from, to, ProofLog);
    Object.freeze(msg);
    return msg;
  }

  public static fromJSON({
    from,
    to,
    ProofLog,
  }: SignMessageForRound4JSON): SignMessageForRound4 {
    const msg = new SignMessageForRound4(
      from, to, ZkLogstarProof.fromJSON(ProofLog),
    );
    Object.freeze(msg);
    return msg;
  }

  public toJSON(): SignMessageForRound4JSON {
    return {
      from: this.from,
      to: this.to,
      ProofLog: this.ProofLog.toJSON(),
    };
  }
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

    const broadcasts: [SignBroadcastForRound5] = [
      SignBroadcastForRound5.from({
        from: this.session.selfId,
        SigmaShare: sigmaShare,
      }),
    ];

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
