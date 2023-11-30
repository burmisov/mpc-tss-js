import { secp256k1 } from '@noble/curves/secp256k1';
import { AffinePoint, AffinePointSerialized } from './common.types.js';
import { PaillierPublicKey, PaillierPublicKeySerialized, PaillierSecretKey, PaillierSecretKeySerialized, paillierPublicKeyFromSerialized, paillierSecretKeyFromSerialized } from './paillier.js';
import { PedersenParameters, PedersenParametersSerialized, pedersenParametersFromSerialized } from './pedersen.js';
import { lagrange } from './polynomial/lagrange.js';

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

const deserializePartyPublicKeyConfig = (
  serialized: PartyPublicKeyConfigSerialized
): PartyPublicKeyConfig => {
  return {
    partyId: serialized.partyId,
    ecdsa: {
      x: BigInt('0x' + serialized.ecdsa.xHex),
      y: BigInt('0x' + serialized.ecdsa.yHex),
    },
    elgamal: {
      x: BigInt('0x' + serialized.elgamal.xHex),
      y: BigInt('0x' + serialized.elgamal.yHex),
    },
    paillier: paillierPublicKeyFromSerialized(serialized.paillier),
    pedersen: pedersenParametersFromSerialized(serialized.pedersen),
  };
}

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

export const deserializePartySecretKeyConfig = (
  serialized: PartySecretKeyConfigSerialized
): PartySecretKeyConfig => {
  const publicPartyData = Object.fromEntries(
    Object.entries(serialized.publicPartyData)
      .map(([partyId, partyPublicKeyConfigSerialized]) => (
        [partyId, deserializePartyPublicKeyConfig(partyPublicKeyConfigSerialized)]
      ))
  );

  return {
    curve: serialized.curve,
    partyId: serialized.partyId,
    threshold: serialized.threshold,
    ecdsa: BigInt('0x' + serialized.ecdsaHex),
    elgamal: BigInt('0x' + serialized.elgamalHex),
    paillier: paillierSecretKeyFromSerialized(serialized.paillier),
    rid: BigInt('0x' + serialized.ridHex),
    chainKey: BigInt('0x' + serialized.chainKeyHex),
    publicPartyData,
  };
}

export const otherPartyIds = (
  partyIds: Array<PartyId>, selfId: PartyId,
): Array<PartyId> => {
  return partyIds.filter(partyId => partyId !== selfId);
}

export const getPublicPoint = (
  publicPartyData: Record<string, PartyPublicKeyConfig>
): AffinePoint => {
  let sum = secp256k1.ProjectivePoint.ZERO;
  const partyIds = Object.keys(publicPartyData).sort();
  const lag = lagrange(partyIds);
  for (const partyId of partyIds) {
    const partyPoint = secp256k1.ProjectivePoint.fromAffine(
      publicPartyData[partyId].ecdsa
    ).multiply(lag[partyId]);
    sum = sum.add(partyPoint);
  }
  return sum.toAffine();
};
