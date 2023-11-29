import { secp256k1 } from '@noble/curves/secp256k1';

import { PartyId, PartySecretKeyConfig } from "../keyConfig.js";
import { lagrange } from '../lagrange.js';
import Fn from '../Fn.js';
import { SignPartyInputRound1 } from './SignerRound1.js';
import { Hasher } from '../Hasher.js';
import { randBetween } from 'bigint-crypto-utils';
import { SignRequest } from './sign.js';

export class SignSession {
  // private signRequest: SignRequest;
  // private keyConfig: PartySecretKeyConfig;

  public currentRound = 'round1';
  public curve = 'secp256k1';
  public finalRound = 'round5';
  public partyIds: Array<PartyId>;
  public protocolId = 'cmp/sign';
  public selfId: PartyId;
  public sessionId: bigint;
  public threshold: number;
  public hasher: Hasher;

  public inputForRound1: SignPartyInputRound1;

  constructor(
    signRequest: SignRequest,
    keyConfig: PartySecretKeyConfig,
  ) {
    // this.signRequest = signRequest;
    // this.keyConfig = keyConfig;

    this.partyIds = signRequest.signerIds;
    this.selfId = keyConfig.partyId;
    this.threshold = keyConfig.threshold;

    this.sessionId = randBetween(2n ** 256n);

    const lag = lagrange(signRequest.signerIds);
    let publicKey = secp256k1.ProjectivePoint.ZERO;

    // TODO: see if can just reuse keyConfig.publicPartyData
    const partiesPublic: SignPartyInputRound1['partiesPublic'] = {};
    signRequest.signerIds.forEach(partyId => {
      const partyData = keyConfig.publicPartyData[partyId];
      const point = secp256k1.ProjectivePoint.fromAffine(partyData.ecdsa);
      const scaledPoint = point.multiply(lag[partyId]);
      publicKey = publicKey.add(scaledPoint);
      partiesPublic[partyId] = {
        ecdsa: scaledPoint.toAffine(),
        paillier: partyData.paillier,
        pedersen: partyData.pedersen,
      };
    });

    // TODO: make consistent with original
    this.hasher = Hasher.create().update('CMP-BLAKE');
    this.hasher.update(keyConfig.rid);
    this.hasher.update(this.protocolId);
    this.hasher.update(this.curve);
    this.hasher.update(BigInt(this.threshold));
    for (let partyId of signRequest.signerIds) {
      this.hasher.update(partyId);
      this.hasher.update(partiesPublic[partyId].ecdsa);
      this.hasher.update(partiesPublic[partyId].paillier);
      this.hasher.update(partiesPublic[partyId].pedersen);
    }
    this.hasher.update(signRequest.message);

    this.inputForRound1 = {
      message: signRequest.message,
      secretEcdsa: Fn.mul(lag[keyConfig.partyId], keyConfig.ecdsa),
      secretPaillier: keyConfig.paillier,
      publicKey: publicKey.toAffine(),
      partiesPublic,
    };
  }

  public cloneHashForId(id: PartyId): Hasher {
    return this.hasher.clone().update(id);
  }
}
