import { SignPartyInputRound1 } from './sign.js';
import { AffinePoint } from "../common.types.js";
import { SignPartySession } from "./sign.js";
import { PartyId, otherPartyIds } from '../keyConfig.js';
import { ZkEncProof, ZkEncPublic, zkEncVerifyProof } from '../zk/enc.js';
import { validateCiphertext } from '../paillier.js';
import {
  SignBroadcastForRound3, SignInputForRound3, SignMessageForRound3,
} from './SignerRound3.js';
import { mtaProveAffG } from '../mta.js';
import {
  ZkLogstarPrivate, ZkLogstarPublic, zkLogstarCreateProof,
} from '../zk/logstar.js';

export type SignPartyInputRound2 = {
  inputForRound1: SignPartyInputRound1;
  K: bigint; // Paillier ciphertext
  G: bigint; // Paillier ciphertext
  BigGammaShare: AffinePoint;
  GammaShare: bigint;
  KShare: bigint;
  KNonce: bigint;
  GNonce: bigint;
};

export type SignBroadcastForRound2 = {
  from: PartyId;
  K: bigint; // Paillier ciphertext
  G: bigint; // Paillier ciphertext
};

export type SignMessageForRound2 = {
  from: PartyId;
  to: PartyId;
  proofEnc: ZkEncProof;
};

export type SignPartyOutputRound2 = {
  broadcasts: Array<SignBroadcastForRound3>;
  messages: Array<SignMessageForRound3>;
  inputForRound3: SignInputForRound3;
};

export class SignerRound2 {
  public session: SignPartySession;
  private roundInput: SignPartyInputRound2;

  private K: Record<PartyId, bigint> = {};
  private G: Record<PartyId, bigint> = {};

  constructor(session: SignPartySession, roundInput: SignPartyInputRound2) {
    this.roundInput = roundInput;
    this.session = session;
  }

  public handleBroadcastMessage(bmsg: SignBroadcastForRound2): void {
    const paillierFrom = this.roundInput
      .inputForRound1.partiesPublic[bmsg.from].paillier;
    const cipherTextsValid = validateCiphertext(paillierFrom, bmsg.K) &&
      validateCiphertext(paillierFrom, bmsg.G);
    if (!cipherTextsValid) {
      throw new Error(`Invalid ciphertexts from party ${bmsg.from}`);
    }
    this.K[bmsg.from] = bmsg.K;
    this.G[bmsg.from] = bmsg.G;
  }

  public handleDirectMessage(msg: SignMessageForRound2): void {
    if (msg.to !== this.session.selfId) {
      throw new Error(
        `Received message for party ${msg.to} but I am party ${this.session.selfId}`
      );
    }
    if (msg.from === this.session.selfId) {
      throw new Error(`Received message from myself`);
    }

    const { proofEnc: proof } = msg;
    const pub: ZkEncPublic = {
      K: this.K[msg.from],
      prover: this.roundInput.inputForRound1.partiesPublic[msg.from].paillier,
      aux: this.roundInput.inputForRound1.partiesPublic[msg.to].pedersen,
    };
    const verified = zkEncVerifyProof(proof, pub);

    if (!verified) {
      throw new Error(`Invalid proof from party ${msg.from}`);
    }
  }

  public process(): SignPartyOutputRound2 {
    // TODO: check if all parties have sent their messages

    const broadcasts: [SignBroadcastForRound3] = [
      {
        from: this.session.selfId,
        BigGammaShare: this.roundInput.BigGammaShare,
      },
    ];

    const messages: Array<SignMessageForRound3> = [];

    const otherIds = otherPartyIds(
      this.session.partyIds, this.session.selfId
    );
    const pubData = this.roundInput.inputForRound1.partiesPublic;
    const mtaOuts = otherIds.map(partyId => {
      const {
        Beta: DeltaBeta,
        D: DeltaD,
        F: DeltaF,
        proof: DeltaProof,
      } = mtaProveAffG(
        this.roundInput.GammaShare,
        this.roundInput.BigGammaShare,
        this.K[partyId],
        this.roundInput.inputForRound1.secretPaillier,
        pubData[partyId].paillier,
        pubData[partyId].pedersen,
      );

      const {
        Beta: ChiBeta,
        D: ChiD,
        F: ChiF,
        proof: ChiProof,
      } = mtaProveAffG(
        this.roundInput.inputForRound1.secretEcdsa,
        pubData[this.session.selfId].ecdsa,
        this.K[partyId],
        this.roundInput.inputForRound1.secretPaillier,
        pubData[partyId].paillier,
        pubData[partyId].pedersen,
      );

      const pub: ZkLogstarPublic = {
        C: this.G[this.session.selfId],
        X: this.roundInput.BigGammaShare,
        prover: this.roundInput.inputForRound1.secretPaillier.publicKey,
        aux: pubData[partyId].pedersen,
      };
      const priv: ZkLogstarPrivate = {
        X: this.roundInput.GammaShare,
        Rho: this.roundInput.GNonce,
      };
      const proof = zkLogstarCreateProof(pub, priv);

      messages.push({
        from: this.session.selfId,
        to: partyId,
        ChiD, ChiF, ChiProof, DeltaD, DeltaF, DeltaProof, ProofLog: proof,
      });

      return { DeltaBeta, ChiBeta, partyId };
    });

    const DeltaShareBetas: Record<PartyId, bigint> = {};
    const ChiShareBetas: Record<PartyId, bigint> = {};
    mtaOuts.forEach(({ DeltaBeta, ChiBeta, partyId }) => {
      DeltaShareBetas[partyId] = DeltaBeta;
      ChiShareBetas[partyId] = ChiBeta;
    });

    const roundOutput: SignPartyOutputRound2 = {
      broadcasts,
      messages,
      inputForRound3: {
        DeltaShareBetas,
        ChiShareBetas,
        K: this.K,
        G: this.G,
        inputForRound2: this.roundInput,
      },
    };

    this.session.currentRound = 'round3';

    return roundOutput;
  }
}
