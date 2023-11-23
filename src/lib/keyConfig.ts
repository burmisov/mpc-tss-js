import { AffinePoint, AffinePointSerialized } from './common.types.js';
import { PaillierPublicKey, PaillierPublicKeySerialized, PaillierSecretKey, PaillierSecretKeySerialized } from './paillier.js';
import { PedersenParameters, PedersenParametersSerialized } from './pedersen.js';

export type PartyId = string;

export type PartyPublicKeyConfig = {
  partyId: PartyId,
  ecdsa: AffinePoint,
  elgamal: AffinePoint,
  paillier: PaillierPublicKey,
  pedersen: PedersenParameters,
};

export type PartyPublicKeyConfigSerialized = {
  partyId: string,
  ecdsa: AffinePointSerialized
  elgamal: AffinePointSerialized,
  paillier: PaillierPublicKeySerialized,
  pedersen: PedersenParametersSerialized,
};

export type PartySecretKeyConfig = {
  curve: 'secp256k1',
  partyId: PartyId,
  threshold: number,
  ecdsa: bigint,
  elgamal: bigint,
  paillier: PaillierSecretKey,
  rid: bigint, // TODO
  chainKey: bigint, // TODO
  publicPartyData: Record<PartyId, PartyPublicKeyConfig>,
};

export type PartySecretKeyConfigSerialized = {
  curve: 'secp256k1',
  partyId: string,
  threshold: number,
  ecdsaHex: string,
  elgamalHex: string,
  paillier: PaillierSecretKeySerialized,
  ridHex: string, // TODO
  chainKeyHex: string, // TODO
  publicPartyData: Record<string, PartyPublicKeyConfigSerialized>,
};
