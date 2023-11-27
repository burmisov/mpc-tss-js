import { blake3 } from '@noble/hashes/blake3';
import { hexToBytes } from '@noble/hashes/utils';

import { AffinePoint } from "../common.types.js"
import { PartyId, PartySecretKeyConfig } from "../keyConfig.js";
import { PaillierPublicKey, PaillierSecretKey } from "../paillier.js"
import { PedersenParameters } from "../pedersen.js"
import { secp256k1 } from '@noble/curves/secp256k1';
import { lagrange } from '../lagrange.js';
import { SignPartyInputRound2 } from './SignerRound2.js';
import { SignBroadcastForRound2, SignMessageForRound2 } from './SignerRound2.js';
import Fn from '../Fn.js';

const Fp = secp256k1.CURVE.Fp;

type Hasher = ReturnType<typeof blake3.create>;

export type SignRequest = {
  message: Uint8Array,
  // publicKey: AffinePoint, // TODO: should we have it here?
  signerIds: Array<PartyId>,
};

export type SignRequestSerialized = {
  messageHex: string,
  // publicKey: AffinePointSerialized,
  signerIds: Array<string>,
};

export const deserializeSignRequest = (
  serialized: SignRequestSerialized
): SignRequest => {
  return {
    message: hexToBytes(serialized.messageHex),
    // publicKey: {
    //   x: BigInt('0x' + serialized.publicKey.xHex),
    //   y: BigInt('0x' + serialized.publicKey.yHex),
    // },
    signerIds: serialized.signerIds,
  };
};

export type SignPartyInputRound1 = {
  publicKey: AffinePoint,
  secretEcdsa: bigint,
  secretPaillier: PaillierSecretKey,
  partiesPublic: Record<string, {
    paillier: PaillierPublicKey,
    pedersen: PedersenParameters,
    ecdsa: AffinePoint,
  }>,
  message: Uint8Array,
};

export type SignPartyOutputRound1 = {
  broadcasts: [SignBroadcastForRound2],
  messages: Array<SignMessageForRound2>,
  inputForRound2: SignPartyInputRound2,
};

export type SignPartySession = {
  protocolId: 'cmp/sign',
  curve: 'secp256k1',
  sessionId: string,
  message: Uint8Array,
  partyIds: Array<PartyId>,
  threshold: number,
  selfId: PartyId,
  currentRound: 'round1' | 'round2' | 'round3' | 'round4' | 'round5',
  finalRound: 'round5',
  hasher: Hasher,
};

export const newSignSession = (
  signRequest: SignRequest,
  keyConfig: PartySecretKeyConfig,
): {
  session: SignPartySession,
  inputForRound1: SignPartyInputRound1,
} => {
  const lag = lagrange(signRequest.signerIds);
  // console.log('lag full', lag);
  let publicKey = secp256k1.ProjectivePoint.ZERO;

  // TODO: see if can just reuse keyConfig.publicPartyData
  const partiesPublic: SignPartyInputRound1['partiesPublic'] = Object.fromEntries(
    Object.entries(keyConfig.publicPartyData).map(([partyId, partyData]) => {
      const point = secp256k1.ProjectivePoint.fromAffine(partyData.ecdsa);
      const scaledPoint = point.multiply(lag[partyId]);
      publicKey = publicKey.add(scaledPoint);
      return [partyId, {
        ecdsa: scaledPoint.toAffine(),
        paillier: partyData.paillier,
        pedersen: partyData.pedersen,
      }];
    })
  );

  const inputForRound1: SignPartyInputRound1 = {
    message: signRequest.message,
    secretEcdsa: Fn.mul(lag[keyConfig.partyId], keyConfig.ecdsa),
    secretPaillier: keyConfig.paillier,
    publicKey,
    partiesPublic,
  };

  const session: SignPartySession = {
    currentRound: 'round1',
    curve: 'secp256k1',
    finalRound: 'round5',
    message: signRequest.message,
    partyIds: signRequest.signerIds,
    protocolId: 'cmp/sign',
    selfId: keyConfig.partyId,
    sessionId: Math.random().toString().slice(2), // TODO: make proper random id
    threshold: keyConfig.threshold,
    hasher: blake3.create({}).update('CMP-BLAKE'),
  };

  return {
    inputForRound1,
    session,
  };
}
