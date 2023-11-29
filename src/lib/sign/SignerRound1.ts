import { SignSession } from "./SignSession.js";
import {
  SignBroadcastForRound2,
  SignMessageForRound2,
  SignPartyInputRound2,
} from './SignerRound2.js';
import {
  PaillierPublicKey, PaillierSecretKey,
  paillierEncrypt,
} from "../paillier.js";
import { ZkEncPrivate, ZkEncPublic, zkEncCreateProof } from "../zk/enc.js";
import { sampleScalarPointPair, sampleScalar } from "../sample.js";
import { AffinePoint } from "../common.types.js";
import { PedersenParameters } from "../pedersen.js";

export type SignPartyInputRound1 = {
  publicKey: AffinePoint;
  secretEcdsa: bigint;
  secretPaillier: PaillierSecretKey;
  partiesPublic: Record<string, {
    paillier: PaillierPublicKey;
    pedersen: PedersenParameters;
    ecdsa: AffinePoint;
  }>;
  message: Uint8Array;
};

export type SignPartyOutputRound1 = {
  broadcasts: [SignBroadcastForRound2];
  messages: Array<SignMessageForRound2>;
  inputForRound2: SignPartyInputRound2;
};

export class SignerRound1 {
  public session: SignSession;
  private roundInput: SignPartyInputRound1;

  constructor(
    session: SignSession,
    roundInput: SignPartyInputRound1,
  ) {
    this.session = session;
    this.roundInput = roundInput;
  }

  public process(): SignPartyOutputRound1 {
    const [GammaShare, BigGammaShare] = sampleScalarPointPair();
    const { ciphertext: G, nonce: GNonce } = paillierEncrypt(
      this.roundInput.partiesPublic[this.session.selfId].paillier,
      GammaShare,
    );

    const KShare = sampleScalar();
    const { ciphertext: K, nonce: KNonce } = paillierEncrypt(
      this.roundInput.partiesPublic[this.session.selfId].paillier,
      KShare,
    );

    const broadcast: SignBroadcastForRound2 = {
      from: this.session.selfId,
      K, G,
    };

    const messages: Array<SignMessageForRound2> = [];

    Object.entries(this.roundInput.partiesPublic).forEach(
      ([partyId, partyPublic]) => {
        // Go over other parties
        if (partyId === this.session.selfId) {
          return;
        }

        const zkPublic: ZkEncPublic = {
          K,
          prover: this.roundInput.partiesPublic[this.session.selfId].paillier,
          aux: partyPublic.pedersen,
        };
        const zkPrivate: ZkEncPrivate = {
          k: KShare,
          rho: KNonce,
        };
        const proof = zkEncCreateProof(
          zkPublic,
          zkPrivate,
          this.session.cloneHashForId(this.session.selfId),
        );
        const message: SignMessageForRound2 = {
          from: this.session.selfId,
          to: partyId,
          proofEnc: proof,
        };
        messages.push(message);
      }
    );

    this.session.currentRound = 'round2';

    return {
      broadcasts: [broadcast],
      messages,
      inputForRound2: {
        inputForRound1: this.roundInput,
        K,
        G,
        BigGammaShare,
        GammaShare,
        KShare,
        KNonce,
        GNonce,
      },
    };
  };
}
