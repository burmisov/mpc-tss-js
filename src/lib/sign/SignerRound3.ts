import { secp256k1 } from "@noble/curves/secp256k1";
import { AffinePoint, AffinePointJSON } from "../common.types.js";
import { PartyId, otherPartyIds } from "../keyConfig.js";
import {
  ZkAffgProof, ZkAffgProofJSON, ZkAffgPublic, zkAffgVerifyProof,
} from "../zk/affg.js";
import {
  ZkLogstarPrivate, ZkLogstarProof, ZkLogstarProofJSON, ZkLogstarPublic,
  zkLogstarCreateProof, zkLogstarVerifyProof,
} from "../zk/logstar.js";
import { isIdentity, pointFromJSON, pointToJSON } from "../curve.js";
import { SignPartyInputRound2 } from "./SignerRound2.js";
import Fn from "../Fn.js";
import {
  SignBroadcastForRound4, SignInputForRound4, SignMessageForRound4,
} from "./SignerRound4.js";
import { SignSession } from "./SignSession.js";

export type SignBroadcastForRound3JSON = {
  from: string,
  BigGammaShare: AffinePointJSON,
};

export class SignBroadcastForRound3 {
  public readonly from: PartyId;
  public readonly BigGammaShare: AffinePoint;

  private constructor(from: PartyId, BigGammaShare: AffinePoint) {
    this.from = from;
    this.BigGammaShare = BigGammaShare;
  }

  public static from({
    from,
    BigGammaShare,
  }: {
    from: PartyId,
    BigGammaShare: AffinePoint,
  }): SignBroadcastForRound3 {
    const bmsg = new SignBroadcastForRound3(from, BigGammaShare);
    Object.freeze(bmsg);
    return bmsg;
  }

  public static fromJSON(json: SignBroadcastForRound3JSON): SignBroadcastForRound3 {
    return SignBroadcastForRound3.from({
      from: json.from as PartyId,
      BigGammaShare: pointFromJSON(json.BigGammaShare),
    });
  }

  public toJSON(): SignBroadcastForRound3JSON {
    return {
      from: this.from,
      BigGammaShare: pointToJSON(this.BigGammaShare),
    };
  }
};

export type SignMessageForRound3JSON = {
  from: string,
  to: string,

  DeltaDhex: string, // Ciphertext
  DeltaFhex: string, // Ciphertext
  DeltaProof: ZkAffgProofJSON,
  ChiDhex: string, // Ciphertext
  ChiFhex: string, // Ciphertext
  ChiProof: ZkAffgProofJSON,
  ProofLog: ZkLogstarProofJSON,
};

export class SignMessageForRound3 {
  public readonly from: PartyId;
  public readonly to: PartyId;
  public readonly DeltaD: bigint; // Ciphertext
  public readonly DeltaF: bigint; // Ciphertext
  public readonly DeltaProof: ZkAffgProof;
  public readonly ChiD: bigint; // Ciphertext
  public readonly ChiF: bigint; // Ciphertext
  public readonly ChiProof: ZkAffgProof;
  public readonly ProofLog: ZkLogstarProof;

  private constructor(
    from: PartyId,
    to: PartyId,
    DeltaD: bigint,
    DeltaF: bigint,
    DeltaProof: ZkAffgProof,
    ChiD: bigint,
    ChiF: bigint,
    ChiProof: ZkAffgProof,
    ProofLog: ZkLogstarProof,
  ) {
    this.from = from;
    this.to = to;
    this.DeltaD = DeltaD;
    this.DeltaF = DeltaF;
    this.DeltaProof = DeltaProof;
    this.ChiD = ChiD;
    this.ChiF = ChiF;
    this.ChiProof = ChiProof;
    this.ProofLog = ProofLog;
  }

  public static from({
    from,
    to,
    DeltaD,
    DeltaF,
    DeltaProof,
    ChiD,
    ChiF,
    ChiProof,
    ProofLog,
  }: {
    from: PartyId,
    to: PartyId,
    DeltaD: bigint,
    DeltaF: bigint,
    DeltaProof: ZkAffgProof,
    ChiD: bigint,
    ChiF: bigint,
    ChiProof: ZkAffgProof,
    ProofLog: ZkLogstarProof,
  }): SignMessageForRound3 {
    const msg = new SignMessageForRound3(
      from, to, DeltaD, DeltaF, DeltaProof, ChiD, ChiF, ChiProof, ProofLog
    );
    Object.freeze(msg);
    return msg;
  }

  public static fromJSON(json: SignMessageForRound3JSON): SignMessageForRound3 {
    return SignMessageForRound3.from({
      from: json.from as PartyId,
      to: json.to as PartyId,
      DeltaD: BigInt(`0x${json.DeltaDhex}`),
      DeltaF: BigInt(`0x${json.DeltaFhex}`),
      DeltaProof: ZkAffgProof.fromJSON(json.DeltaProof),
      ChiD: BigInt(`0x${json.ChiDhex}`),
      ChiF: BigInt(`0x${json.ChiFhex}`),
      ChiProof: ZkAffgProof.fromJSON(json.ChiProof),
      ProofLog: ZkLogstarProof.fromJSON(json.ProofLog),
    });
  }

  public toJSON(): SignMessageForRound3JSON {
    return {
      from: this.from,
      to: this.to,
      DeltaDhex: this.DeltaD.toString(16),
      DeltaFhex: this.DeltaF.toString(16),
      DeltaProof: this.DeltaProof.toJSON(),
      ChiDhex: this.ChiD.toString(16),
      ChiFhex: this.ChiF.toString(16),
      ChiProof: this.ChiProof.toJSON(),
      ProofLog: this.ProofLog.toJSON(),
    };
  }
};

export type SignInputForRound3 = {
  DeltaShareBetas: Record<PartyId, bigint>;
  ChiShareBetas: Record<PartyId, bigint>;
  K: Record<PartyId, bigint>;
  G: Record<PartyId, bigint>;
  inputForRound2: SignPartyInputRound2;
};

export type SignPartyOutputRound3 = {
  broadcasts: Array<SignBroadcastForRound4>,
  messages: Array<SignMessageForRound4>,
  inputForRound4: SignInputForRound4,
};

export class SignerRound3 {
  public session: SignSession;
  private roundInput: SignInputForRound3;

  private BigGammaShare: Record<PartyId, AffinePoint> = {};
  private DeltaShareAlpha: Record<PartyId, bigint> = {};
  private ChiShareAlpha: Record<PartyId, bigint> = {};

  constructor(session: SignSession, roundInput: SignInputForRound3) {
    this.roundInput = roundInput;
    this.session = session;
  }

  public handleBroadcastMessage(bmsg: SignBroadcastForRound3): void {
    const point = secp256k1.ProjectivePoint.fromAffine(bmsg.BigGammaShare);
    if (isIdentity(point)) {
      throw new Error("BigGammaShare is identity");
    }
    this.BigGammaShare[bmsg.from] = bmsg.BigGammaShare;
  }

  public handleDirectMessage(msg: SignMessageForRound3): void {
    if (msg.to !== this.session.selfId) {
      throw new Error(
        `Message intended for ${msg.to} but received by ${this.session.selfId}`
      );
    }

    // TODO: deal with this mess (via session? or denormalize)
    const pubData = this.roundInput.inputForRound2.inputForRound1.partiesPublic;

    const deltaAffgPub: ZkAffgPublic = {
      Kv: this.roundInput.K[msg.to],
      Dv: msg.DeltaD,
      Fp: msg.DeltaF,
      Xp: this.BigGammaShare[msg.from],
      prover: pubData[msg.from].paillier,
      verifier: pubData[msg.to].paillier,
      aux: pubData[msg.to].pedersen,
    };
    const deltaVerified = zkAffgVerifyProof(
      msg.DeltaProof, deltaAffgPub, this.session.cloneHashForId(msg.from),
    );
    if (!deltaVerified) {
      throw new Error(`Failed to validate affg proof for Delta MtA from ${msg.from}`);
    }

    const chiAffgPub: ZkAffgPublic = {
      Kv: this.roundInput.K[msg.to],
      Dv: msg.ChiD,
      Fp: msg.ChiF,
      Xp: pubData[msg.from].ecdsa,
      prover: pubData[msg.from].paillier,
      verifier: pubData[msg.to].paillier,
      aux: pubData[msg.to].pedersen,
    };
    const chiVerified = zkAffgVerifyProof(
      msg.ChiProof, chiAffgPub, this.session.cloneHashForId(msg.from),
    );
    if (!chiVerified) {
      throw new Error(`Failed to validate affg proof for Chi MtA from ${msg.from}`);
    }

    const logPub: ZkLogstarPublic = {
      C: this.roundInput.G[msg.from],
      X: this.BigGammaShare[msg.from],
      prover: pubData[msg.from].paillier,
      aux: pubData[msg.to].pedersen,
    };
    const logVerified = zkLogstarVerifyProof(
      msg.ProofLog, logPub, this.session.cloneHashForId(msg.from),
    );
    if (!logVerified) {
      throw new Error(`Failed to validate log proof from ${msg.from}`);
    }

    // Store the verified values (TODO: split into separate function?)
    // TODO: handle decryption errors locally
    const DeltaShareAlpha =
      this.roundInput.inputForRound2.inputForRound1.secretPaillier.decrypt(msg.DeltaD);
    const ChiShareAlpha =
      this.roundInput.inputForRound2.inputForRound1.secretPaillier.decrypt(msg.ChiD);
    this.DeltaShareAlpha[msg.from] = DeltaShareAlpha;
    this.ChiShareAlpha[msg.from] = ChiShareAlpha;
  }

  public process(): SignPartyOutputRound3 {
    let Gamma = secp256k1.ProjectivePoint.ZERO;
    Object.values(this.BigGammaShare).forEach(afPoint => {
      const point = secp256k1.ProjectivePoint.fromAffine(afPoint);
      Gamma = Gamma.add(point);
    });

    const BigDeltaShare = Gamma.multiply(
      this.roundInput.inputForRound2.KShare,
    );

    let DeltaShare = this.roundInput.inputForRound2.GammaShare *
      this.roundInput.inputForRound2.KShare;

    let ChiShare = this.roundInput.inputForRound2.inputForRound1.secretEcdsa *
      this.roundInput.inputForRound2.KShare;

    const otherIds = otherPartyIds(
      this.session.partyIds, this.session.selfId
    );
    otherIds.forEach(partyId => {
      DeltaShare = DeltaShare + this.DeltaShareAlpha[partyId];
      DeltaShare = DeltaShare + this.roundInput.DeltaShareBetas[partyId];
      ChiShare = ChiShare + this.ChiShareAlpha[partyId];
      ChiShare = ChiShare + this.roundInput.ChiShareBetas[partyId];
    });

    const priv: ZkLogstarPrivate = {
      X: this.roundInput.inputForRound2.KShare,
      Rho: this.roundInput.inputForRound2.KNonce,
    };

    const DeltaShareScalar = Fn.mod(DeltaShare);
    const broadcasts: [SignBroadcastForRound4] = [
      SignBroadcastForRound4.from({
        from: this.session.selfId,
        DeltaShare: DeltaShareScalar,
        BigDeltaShare: BigDeltaShare.toAffine(),
      }),
    ];

    const messages: Array<SignMessageForRound4> = [];
    const pubData = this.roundInput.inputForRound2.inputForRound1.partiesPublic
    otherIds.forEach(partyId => {
      const pub: ZkLogstarPublic = {
        C: this.roundInput.K[this.session.selfId],
        X: BigDeltaShare.toAffine(),
        G: Gamma.toAffine(),
        prover: pubData[this.session.selfId].paillier,
        aux: pubData[partyId].pedersen,
      };
      const proof = zkLogstarCreateProof(
        pub, priv, this.session.cloneHashForId(this.session.selfId),
      );
      messages.push(SignMessageForRound4.from({
        from: this.session.selfId,
        to: partyId,
        ProofLog: proof,
      }));
    });

    this.session.currentRound = 'round4';

    return {
      broadcasts,
      messages,
      inputForRound4: {
        DeltaShare,
        BigDeltaShare,
        Gamma: Gamma.toAffine(),
        ChiShare: Fn.mod(ChiShare),
        inputForRound3: this.roundInput,
      },
    };
  };
};
