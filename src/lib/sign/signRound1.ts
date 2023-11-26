import { secp256k1 } from "@noble/curves/secp256k1";
import { randBetween } from "bigint-crypto-utils";

import {
  SignPartySession, SignPartyInputRound1, SignPartyOutputRound1,
  SignBroadcastForRound2, SignMessageForRound2,
} from "./sign.js";
import Fn from "../Fn.js";
import { AffinePoint } from "../common.types.js";
import { paillierEncrypt } from "../paillier.js";
import { ZkEncPrivate, ZkEncPublic, zkEncCreateProof } from "../zk/enc.js";

export default (
  roundInput: SignPartyInputRound1,
  session: SignPartySession,
): {
  roundOutput: SignPartyOutputRound1,
  session: SignPartySession,
} => {
  const [GammaShare, BigGammaShare] = sampleScalarPointPair();
  const { ciphertext: G, nonce: GNonce } = paillierEncrypt(
    roundInput.partiesPublic[session.selfId].paillier,
    GammaShare,
  );

  const KShare = sampleScalar();
  const { ciphertext: K, nonce: KNonce } = paillierEncrypt(
    roundInput.partiesPublic[session.selfId].paillier,
    KShare,
  );

  const broadcast: SignBroadcastForRound2 = {
    source: session.selfId,
    K, G,
  };

  const messages: Array<SignMessageForRound2> = [];

  Object.entries(roundInput.partiesPublic).forEach(([partyId, partyPublic]) => {
    // Go over other parties
    if (partyId === session.selfId) {
      return;
    }

    const zkPublic: ZkEncPublic = {
      K,
      prover: roundInput.partiesPublic[session.selfId].paillier,
      aux: partyPublic.pedersen,
    };
    const zkPrivate: ZkEncPrivate = {
      k: KShare,
      rho: KNonce,
    };
    const proof = zkEncCreateProof(zkPublic, zkPrivate);
    const message: SignMessageForRound2 = {
      source: session.selfId,
      destination: partyId,
      proofEnc: proof,
    };
    messages.push(message);
  })

  const roundOutput: SignPartyOutputRound1 = {
    broadcasts: [broadcast],
    messages,
    inputForRound2: {
      inputForRound1: roundInput,
      K,
      G,
      BigGammaShare,
      GammaShare,
      KShare,
      KNonce,
      GNonce,
    },
  };

  const updatedSession: SignPartySession = {
    ...session,
    currentRound: 'round2',
  };

  return {
    roundOutput,
    session: updatedSession,
  };
};

const sampleScalarPointPair = (): [bigint, AffinePoint] => {
  const scalar = randBetween(Fn.N - 1n);
  const point = secp256k1.ProjectivePoint.BASE.multiply(scalar);
  return [scalar, point.toAffine()];
};

const sampleScalar = (): bigint => randBetween(Fn.N - 1n);
