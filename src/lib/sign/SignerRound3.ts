import { secp256k1 } from "@noble/curves/secp256k1";
import { AffinePoint } from "../common.types.js";
import { PartyId, otherPartyIds } from "../keyConfig.js";
import { ZkAffgProof, ZkAffgPublic, zkAffgVerifyProof } from "../zk/affg.js";
import {
  ZkLogstarPrivate, ZkLogstarProof, ZkLogstarPublic,
  zkLogstarCreateProof, zkLogstarVerifyProof,
} from "../zk/logstar.js";
import { SignPartySession } from "./sign.js";
import { isIdentity } from "../curve.js";
import { SignPartyInputRound2 } from "./SignerRound2.js";
import { paillierDecrypt } from "../paillier.js";
import Fn from "../Fn.js";
import {
  SignBroadcastForRound4, SignInputForRound4, SignMessageForRound4,
} from "./SignerRound4.js";

export type SignBroadcastForRound3 = {
  from: PartyId;
  BigGammaShare: AffinePoint
};

export type SignMessageForRound3 = {
  from: PartyId;
  to: PartyId;

  DeltaD: bigint; // Ciphertext
  DeltaF: bigint; // Ciphertext
  DeltaProof: ZkAffgProof;
  ChiD: bigint; // Ciphertext
  ChiF: bigint; // Ciphertext
  ChiProof: ZkAffgProof;
  ProofLog: ZkLogstarProof;
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
  public session: SignPartySession;
  private roundInput: SignInputForRound3;

  private BigGammaShare: Record<PartyId, AffinePoint> = {};
  private DeltaShareAlpha: Record<PartyId, bigint> = {};
  private ChiShareAlpha: Record<PartyId, bigint> = {};

  constructor(session: SignPartySession, roundInput: SignInputForRound3) {
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
    const deltaVerified = zkAffgVerifyProof(msg.DeltaProof, deltaAffgPub);
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
    const chiVerified = zkAffgVerifyProof(msg.ChiProof, chiAffgPub);
    if (!chiVerified) {
      throw new Error(`Failed to validate affg proof for Chi MtA from ${msg.from}`);
    }

    const logPub: ZkLogstarPublic = {
      C: this.roundInput.G[msg.from],
      X: this.BigGammaShare[msg.from],
      prover: pubData[msg.from].paillier,
      aux: pubData[msg.to].pedersen,
    };
    const logVerified = zkLogstarVerifyProof(msg.ProofLog, logPub);
    if (!logVerified) {
      throw new Error(`Failed to validate log proof from ${msg.from}`);
    }

    // Store the verified values (TODO: split into separate function?)
    // TODO: handle decryption errors locally
    const DeltaShareAlpha = paillierDecrypt(
      this.roundInput.inputForRound2.inputForRound1.secretPaillier,
      msg.DeltaD,
    );
    const ChiShareAlpha = paillierDecrypt(
      this.roundInput.inputForRound2.inputForRound1.secretPaillier,
      msg.ChiD,
    );
    this.DeltaShareAlpha[msg.from] = DeltaShareAlpha;
    this.ChiShareAlpha[msg.from] = ChiShareAlpha;
  }

  public process(): SignPartyOutputRound3 {
    const Gamma = secp256k1.ProjectivePoint.ZERO;
    Object.values(this.BigGammaShare).forEach(afPoint => {
      const point = secp256k1.ProjectivePoint.fromAffine(afPoint);
      Gamma.add(point);
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
    const broadcasts: [SignBroadcastForRound4] = [{
      from: this.session.selfId,
      DeltaShare: DeltaShareScalar,
      BigDeltaShare: BigDeltaShare.toAffine(),
    }];

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
      const proof = zkLogstarCreateProof(pub, priv);
      messages.push({
        from: this.session.selfId,
        to: partyId,
        ProofLog: proof,
      });
    });

    this.session.currentRound = 'round4';

    return {
      broadcasts,
      messages,
      inputForRound4: {
        DeltaShare,
        BigDeltaShare,
        Gamma,
        ChiShare: Fn.mod(ChiShare),
        inputForRound3: this.roundInput,
      },
    };
  };
};
