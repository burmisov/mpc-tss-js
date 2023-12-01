import { secp256k1 } from '@noble/curves/secp256k1';
import { AffinePoint, AffinePointSerialized } from './common.types.js';
import {
  PaillierPublicKey, PaillierPublicKeySerialized, PaillierSecretKey,
  PaillierSecretKeySerialized, paillierPublicKeyFromSerialized,
  paillierPublicKeyToSerialized,
  paillierSecretKeyFromSerialized,
  paillierSecretKeyToSerialized,
} from './paillier.js';
import {
  PedersenParameters, PedersenParametersSerialized, pedersenParametersFromSerialized, pedersenParametersToSerialized,
} from './pedersen.js';
import { lagrange } from './polynomial/lagrange.js';
import { bytesToNumberBE } from '@noble/curves/abstract/utils';
import { utf8ToBytes } from '@noble/hashes/utils';

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

const serializePartyPublicKeyConfig = (
  config: PartyPublicKeyConfig
): PartyPublicKeyConfigSerialized => {
  return {
    partyId: config.partyId,
    ecdsa: {
      xHex: config.ecdsa.x.toString(16),
      yHex: config.ecdsa.y.toString(16),
    },
    elgamal: {
      xHex: config.elgamal.x.toString(16),
      yHex: config.elgamal.y.toString(16),
    },
    paillier: paillierPublicKeyToSerialized(config.paillier),
    pedersen: pedersenParametersToSerialized(config.pedersen),
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

export const serializePartySecretKeyConfig = (
  config: PartySecretKeyConfig
): PartySecretKeyConfigSerialized => {
  const publicPartyData = Object.fromEntries(
    Object.entries(config.publicPartyData)
      .map(([partyId, partyPublicKeyConfig]) => (
        [partyId, serializePartyPublicKeyConfig(partyPublicKeyConfig)]
      ))
  );

  return {
    curve: config.curve,
    partyId: config.partyId,
    threshold: config.threshold,
    ecdsaHex: config.ecdsa.toString(16),
    elgamalHex: config.elgamal.toString(16),
    paillier: paillierSecretKeyToSerialized(config.paillier),
    ridHex: config.rid.toString(16),
    chainKeyHex: config.chainKey.toString(16),
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

export const partyIdToScalar = (
  partyId: PartyId,
): bigint => {
  return bytesToNumberBE(utf8ToBytes(partyId));
}
