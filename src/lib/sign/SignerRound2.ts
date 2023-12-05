import { SignPartyInputRound1 } from './SignerRound1.js';
import { AffinePoint } from "../common.types.js";
import { PartyId, otherPartyIds } from '../keyConfig.js';
import {
  ZkEncProof, ZkEncProofJSON, ZkEncPublic, zkEncVerifyProof,
} from '../zk/enc.js';
import {
  SignBroadcastForRound3, SignInputForRound3, SignMessageForRound3,
} from './SignerRound3.js';
import { mtaProveAffG } from '../mta.js';
import {
  ZkLogstarPrivate, ZkLogstarPublic, zkLogstarCreateProof,
} from '../zk/logstar.js';
import { SignSession } from './SignSession.js';

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

export type SignBroadcastForRound2JSON = {
  from: string,
  Khex: string,
  Ghex: string,
};

export class SignBroadcastForRound2 {
  public readonly from: PartyId;
  public readonly K: bigint; // Paillier ciphertext
  public readonly G: bigint; // Paillier ciphertext

  private constructor(from: PartyId, K: bigint, G: bigint) {
    this.from = from;
    this.K = K;
    this.G = G;
  }

  public static from({
    from,
    K,
    G,
  }: {
    from: PartyId,
    K: bigint,
    G: bigint,
  }): SignBroadcastForRound2 {
    const bmsg = new SignBroadcastForRound2(from, K, G);
    Object.freeze(bmsg);
    return bmsg;
  }

  public static fromJSON(json: SignBroadcastForRound2JSON): SignBroadcastForRound2 {
    return SignBroadcastForRound2.from({
      from: json.from as PartyId,
      K: BigInt(`0x${json.Khex}`),
      G: BigInt(`0x${json.Ghex}`),
    });
  }

  public toJSON(): SignBroadcastForRound2JSON {
    return {
      from: this.from,
      Khex: this.K.toString(16),
      Ghex: this.G.toString(16),
    };
  }
};

export type SignMessageForRound2JSON = {
  from: string,
  to: string,
  proofEnc: ZkEncProofJSON,
};

export class SignMessageForRound2 {
  public readonly from: PartyId;
  public readonly to: PartyId;
  public readonly proofEnc: ZkEncProof;

  private constructor(from: PartyId, to: PartyId, proofEnc: ZkEncProof) {
    this.from = from;
    this.to = to;
    this.proofEnc = proofEnc;
  }

  public static from({
    from,
    to,
    proofEnc,
  }: {
    from: PartyId,
    to: PartyId,
    proofEnc: ZkEncProof,
  }): SignMessageForRound2 {
    const msg = new SignMessageForRound2(from, to, proofEnc);
    Object.freeze(msg);
    return msg;
  }

  public static fromJSON(json: SignMessageForRound2JSON): SignMessageForRound2 {
    return SignMessageForRound2.from({
      from: json.from as PartyId,
      to: json.to as PartyId,
      proofEnc: ZkEncProof.fromJSON(json.proofEnc),
    });
  }

  public toJSON(): SignMessageForRound2JSON {
    return {
      from: this.from,
      to: this.to,
      proofEnc: this.proofEnc.toJSON(),
    };
  }
};

export type SignPartyOutputRound2 = {
  broadcasts: Array<SignBroadcastForRound3>;
  messages: Array<SignMessageForRound3>;
  inputForRound3: SignInputForRound3;
};

export class SignerRound2 {
  public session: SignSession;
  private roundInput: SignPartyInputRound2;

  private K: Record<PartyId, bigint> = {};
  private G: Record<PartyId, bigint> = {};

  constructor(session: SignSession, roundInput: SignPartyInputRound2) {
    this.roundInput = roundInput;
    this.session = session;
  }

  public handleBroadcastMessage(bmsg: SignBroadcastForRound2): void {
    const paillierFrom = this.roundInput
      .inputForRound1.partiesPublic[bmsg.from].paillier;
    const cipherTextsValid = paillierFrom.validateCiphertext(bmsg.K) &&
      paillierFrom.validateCiphertext(bmsg.G);
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
    const verified = zkEncVerifyProof(proof, pub, this.session.cloneHashForId(msg.from));

    if (!verified) {
      throw new Error(`Invalid proof from party ${msg.from}`);
    }
  }

  public process(): SignPartyOutputRound2 {
    // TODO: check if all parties have sent their messages

    const broadcasts: [SignBroadcastForRound3] = [
      SignBroadcastForRound3.from({
        from: this.session.selfId,
        BigGammaShare: this.roundInput.BigGammaShare,
      }),
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
        this.session.cloneHashForId(this.session.selfId),
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
        this.session.cloneHashForId(this.session.selfId),
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
      const proof = zkLogstarCreateProof(
        pub, priv, this.session.cloneHashForId(this.session.selfId),
      );

      messages.push(SignMessageForRound3.from({
        from: this.session.selfId,
        to: partyId,
        ChiD, ChiF, ChiProof, DeltaD, DeltaF, DeltaProof, ProofLog: proof,
      }));

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
