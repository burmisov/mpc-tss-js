import { secp256k1 } from "@noble/curves/secp256k1";

import Fn from "../Fn.js";
import {
  PartyId, PartyPublicKeyConfig, PartySecretKeyConfig, partyIdToScalar,
} from "../keyConfig.js";
import { PaillierPublicKey } from "../paillier.js";
import { PedersenParams } from "../pedersen.js";
import { Exponent } from "../polynomial/exponent.js";
import { ZkFacProof, ZkFacPublic, zkFacVerifyProof } from "../zk/fac.js";
import { ZkModProof, ZkModPublic, zkModVerifyProof } from "../zk/mod.js";
import { ZkPrmProof, ZkPrmPublic, zkPrmVerifyProof } from "../zk/prm.js";
import { KeygenInputForRound3 } from "./KeygenRound3.js";
import { KeygenSession } from "./KeygenSession.js";
import { AffinePoint } from "../common.types.js";
import { ZkSchCommitment, zkSchProve } from "../zk/zksch.js";
import { KeygenBroadcastForRound5, KeygenInputForRound5 } from "./KeygenRound5.js";

export type KeygenBroadcastForRound4 = {
  from: PartyId,
  modProof: ZkModProof,
  prmProof: ZkPrmProof,
};

export type KeygenDirectMessageForRound4 = {
  from: PartyId,
  to: PartyId,
  share: bigint,
  facProof: ZkFacProof,
};

export type KeygenInputForRound4 = {
  inputForRound3: KeygenInputForRound3,
  RID: bigint,
  ChainKey: bigint,
  PedersenPublic: Record<PartyId, PedersenParams>,
  PaillierPublic: Record<PartyId, PaillierPublicKey>,
  vssPolynomials: Record<PartyId, Exponent>,
  ElGamalPublic: Record<PartyId, AffinePoint>,
  SchnorrCommitments: Record<PartyId, ZkSchCommitment>,
};

export type KeygenRound4Output = {
  broadcasts: Array<KeygenBroadcastForRound5>,
  inputForRound5: KeygenInputForRound5,
};

export class KeygenRound4 {
  private ShareReceived: Record<PartyId, bigint> = {};

  constructor(
    private session: KeygenSession,
    private input: KeygenInputForRound4,
  ) { }

  public handleBroadcastMessage(bmsg: KeygenBroadcastForRound4) {
    const { from, modProof, prmProof } = bmsg;

    const modPub: ZkModPublic = {
      N: this.input.PedersenPublic[from].n,
    };
    const modVerified = zkModVerifyProof(
      modProof, modPub, this.session.cloneHashForId(from),
    );
    if (!modVerified) {
      throw new Error(`failed to validate mod proof from ${from}`);
    }

    const prmPub: ZkPrmPublic = { Aux: this.input.PedersenPublic[from] };
    const prmVerified = zkPrmVerifyProof(
      prmProof, prmPub, this.session.cloneHashForId(from),
    );
    if (!prmVerified) {
      throw new Error(`failed to validate prm proof from ${from}`);
    }
  }

  public handleDirectMessage(dmsg: KeygenDirectMessageForRound4) {
    const { from, to, share, facProof } = dmsg;

    // verify
    if (to !== this.session.selfId) {
      throw new Error(`received direct message for ${to} but I am ${this.session.selfId}`);
    }

    if (!this.input.PaillierPublic[to].validateCiphertext(share)) {
      throw new Error(`invalid ciphertext from ${from}`);
    }

    const facPub: ZkFacPublic = {
      N: this.input.PaillierPublic[from].n,
      Aux: this.input.PedersenPublic[to],
    };
    const facVerified = zkFacVerifyProof(
      facProof, facPub, this.session.cloneHashForId(from),
    );
    if (!facVerified) {
      throw new Error(`failed to validate fac proof from ${from}`);
    }

    // store
    const DecryptedShare = this.input.inputForRound3.inputForRound2.paillierSecret.decrypt(
      share,
    );
    const Share = Fn.mod(DecryptedShare);
    if (Share !== DecryptedShare) {
      throw new Error(`decrypted share is not in correct range`);
    }

    const ExpectedPublicShare = this.input.vssPolynomials[from].evaluate(
      partyIdToScalar(this.session.selfId),
    );
    const PublicShare = secp256k1.ProjectivePoint.BASE.multiply(Share);
    if (!secp256k1.ProjectivePoint.fromAffine(ExpectedPublicShare).equals(PublicShare)) {
      throw new Error(`${to} failed to validate VSS share from ${from}`);
    }

    this.ShareReceived[from] = Share;
  }

  public process(): KeygenRound4Output {
    this.ShareReceived[this.session.selfId] = this.input.
      inputForRound3.inputForRound2.selfShare;
    let UpdatedSecretECDSA = 0n;
    if (this.input.inputForRound3.inputForRound2.inputRound1.previousSecretECDSA) {
      // TODO: on refresh
      throw new Error('not implemented');
    }
    for (const j of this.session.partyIds) {
      UpdatedSecretECDSA = Fn.add(UpdatedSecretECDSA, this.ShareReceived[j]);
    }

    const ShamirPublicPolynomials: Exponent[] = [];
    for (const j of this.session.partyIds) {
      ShamirPublicPolynomials.push(this.input.vssPolynomials[j]);
    }

    const ShamirPublicPolynomial = Exponent.sum(ShamirPublicPolynomials);

    const PublicData: Record<PartyId, PartyPublicKeyConfig> = {};
    for (const j of this.session.partyIds) {
      const PublicECDSAShare = ShamirPublicPolynomial.evaluate(
        partyIdToScalar(j),
      );
      if (this.input.inputForRound3.inputForRound2.inputRound1.previousPublicSharesECDSA) {
        // TODO: on refresh
        throw new Error('not implemented');
      }
      PublicData[j] = PartyPublicKeyConfig.from({
        partyId: j,
        ecdsa: PublicECDSAShare,
        elgamal: this.input.ElGamalPublic[j],
        paillier: this.input.PaillierPublic[j],
        pedersen: this.input.PedersenPublic[j],
      });
    }

    const UpdatedConfig = PartySecretKeyConfig.from({
      curve: 'secp256k1',
      partyId: this.session.selfId,
      threshold: this.session.threshold,
      ecdsa: UpdatedSecretECDSA,
      elgamal: this.input.inputForRound3.inputForRound2.elGamalSecret,
      paillier: this.input.inputForRound3.inputForRound2.paillierSecret,
      rid: this.input.RID,
      chainKey: this.input.ChainKey,
      publicPartyData: PublicData,
    });

    const hashTmp = this.session.hasher.clone().updateMulti([
      UpdatedConfig,
      this.session.selfId,
    ]);

    const proof = zkSchProve(
      this.input.inputForRound3.inputForRound2.schnorrRand,
      hashTmp.clone(),
      PublicData[this.session.selfId].ecdsa,
      UpdatedSecretECDSA,
    );

    const broadcasts: Array<KeygenBroadcastForRound5> = [{
      from: this.session.selfId,
      SchnorrResponse: proof,
    }];

    this.session.hasher.updateMulti([
      UpdatedConfig,
    ]);

    return {
      broadcasts,
      inputForRound5: {
        inputForRound4: this.input,
        UpdatedConfig,
      },
    };
  }
}
