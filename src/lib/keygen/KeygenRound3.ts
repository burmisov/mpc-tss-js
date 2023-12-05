import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { Hasher } from "../Hasher.js";
import { AffinePoint, AffinePointJSON } from "../common.types.js";
import { pointFromJSON, pointToJSON } from "../curve.js";
import { PartyId, partyIdToScalar } from "../keyConfig.js";
import { PaillierPublicKey } from "../paillier.js";
import { paillierValidateN } from '../paillierKeygen.js';
import { PedersenParametersJSON, PedersenParams } from "../pedersen.js";
import { Exponent, ExponentJSON } from "../polynomial/exponent.js";
import { ZkFacPrivate, ZkFacPublic, zkFacCreateProof } from "../zk/fac.js";
import { ZkModPrivate, ZkModPublic, zkModCreateProof } from "../zk/mod.js";
import { ZkPrmPrivate, ZkPrmPublic, zkPrmCreateProof } from "../zk/prm.js";
import { ZkSchCommitment, ZkSchCommitmentJSON } from "../zk/zksch.js";
import { KeygenInputForRound2 } from "./KeygenRound2.js";
import {
  KeygenBroadcastForRound4, KeygenDirectMessageForRound4, KeygenInputForRound4,
} from "./KeygenRound4.js";
import { KeygenSession } from "./KeygenSession.js";
import { JSONable } from "../serde.js";

export type KeygenBroadcastForRound3JSON = {
  from: PartyId;
  RIDhex: string;
  Chex: string;
  vssPolynomial: ExponentJSON;
  schnorrCommitment: ZkSchCommitmentJSON;
  elGamalPublic: AffinePointJSON;
  pedersenPublic: PedersenParametersJSON;
  decommitmentHex: string;
};

export class KeygenBroadcastForRound3 implements JSONable {
  public readonly from: PartyId;
  public readonly RID: bigint;
  public readonly C: bigint;
  public readonly vssPolynomial: Exponent;
  public readonly schnorrCommitment: ZkSchCommitment;
  public readonly elGamalPublic: AffinePoint;
  public readonly pedersenPublic: PedersenParams;
  public readonly decommitment: Uint8Array;

  private constructor(
    from: PartyId,
    RID: bigint,
    C: bigint,
    vssPolynomial: Exponent,
    schnorrCommitment: ZkSchCommitment,
    elGamalPublic: AffinePoint,
    pedersenPublic: PedersenParams,
    decommitment: Uint8Array
  ) {
    this.from = from;
    this.RID = RID;
    this.C = C;
    this.vssPolynomial = vssPolynomial;
    this.schnorrCommitment = schnorrCommitment;
    this.elGamalPublic = elGamalPublic;
    this.pedersenPublic = pedersenPublic;
    this.decommitment = decommitment;
  }

  public static from({
    from,
    RID,
    C,
    vssPolynomial,
    schnorrCommitment,
    elGamalPublic,
    pedersenPublic,
    decommitment,
  }: {
    from: PartyId,
    RID: bigint,
    C: bigint,
    vssPolynomial: Exponent,
    schnorrCommitment: ZkSchCommitment,
    elGamalPublic: AffinePoint,
    pedersenPublic: PedersenParams,
    decommitment: Uint8Array,
  }): KeygenBroadcastForRound3 {
    const b = new KeygenBroadcastForRound3(
      from,
      RID,
      C,
      vssPolynomial,
      schnorrCommitment,
      elGamalPublic,
      pedersenPublic,
      decommitment,
    );
    Object.freeze(b);
    return b;
  }

  public toJSON(): KeygenBroadcastForRound3JSON {
    return {
      from: this.from,
      RIDhex: this.RID.toString(16),
      Chex: this.C.toString(16),
      vssPolynomial: this.vssPolynomial.toJSON(),
      schnorrCommitment: this.schnorrCommitment.toJSON(),
      elGamalPublic: pointToJSON(this.elGamalPublic),
      pedersenPublic: this.pedersenPublic.toJSON(),
      decommitmentHex: bytesToHex(this.decommitment),
    };
  }

  public static fromJSON(json: KeygenBroadcastForRound3JSON): KeygenBroadcastForRound3 {
    return KeygenBroadcastForRound3.from({
      from: json.from,
      RID: BigInt(`0x${json.RIDhex}`),
      C: BigInt(`0x${json.Chex}`),
      vssPolynomial: Exponent.fromJSON(json.vssPolynomial),
      schnorrCommitment: ZkSchCommitment.fromJSON(json.schnorrCommitment),
      elGamalPublic: pointFromJSON(json.elGamalPublic),
      pedersenPublic: PedersenParams.fromJSON(json.pedersenPublic),
      decommitment: hexToBytes(json.decommitmentHex),
    });
  }
}

export type KeygenInputForRound3 = {
  inputForRound2: KeygenInputForRound2,
  commitments: Record<PartyId, Uint8Array>,
};

export type KeygenRound3Output = {
  broadcasts: Array<KeygenBroadcastForRound4>,
  directMessages: Array<KeygenDirectMessageForRound4>,
  inputForRound4: KeygenInputForRound4,
};

export class KeygenRound3 {
  private RIDs: Record<PartyId, bigint> = {};
  private ChainKeys: Record<PartyId, bigint> = {};
  private PaillierPublic: Record<PartyId, PaillierPublicKey> = {};
  private Pedersen: Record<PartyId, PedersenParams> = {};
  private vssPolynomials: Record<PartyId, Exponent> = {};
  private SchnorrCommitments: Record<PartyId, ZkSchCommitment> = {};
  private ElGamalPublic: Record<PartyId, AffinePoint> = {};

  constructor(
    private readonly session: KeygenSession,
    private readonly inputForRound3: KeygenInputForRound3,
  ) { }

  public handleBroadcastMessage(bmsg: KeygenBroadcastForRound3): void {
    const from = bmsg.from;

    // TODO: check inputs

    Hasher.validateCommitment(bmsg.decommitment);

    const vssSecret = this.inputForRound3.inputForRound2.inputRound1.vssSecret;
    const vssPolynomial = bmsg.vssPolynomial;
    if ((vssSecret.constant() === 0n) !== (vssPolynomial.isConstant)) {
      throw new Error(`vss polynomial has incorrect constant from ${from}`);
    }
    if (vssPolynomial.degree() !== this.session.threshold) {
      throw new Error(`vss polynomial has incorrect degree ${vssPolynomial.degree()} for threshold ${this.session.threshold} from ${from}`);
    }

    paillierValidateN(bmsg.pedersenPublic.n);

    bmsg.pedersenPublic.validate();

    const decomValid = this.session.cloneHashForId(from).decommit(
      this.inputForRound3.commitments[from],
      bmsg.decommitment,
      [
        bmsg.RID,
        bmsg.C,
        vssPolynomial,
        bmsg.schnorrCommitment.C,
        bmsg.elGamalPublic,
        bmsg.pedersenPublic
      ],
    );
    if (!decomValid) {
      throw new Error(`failed to decommit from ${from}`);
    }

    this.RIDs[from] = bmsg.RID;
    this.ChainKeys[from] = bmsg.C;
    this.PaillierPublic[from] = PaillierPublicKey.fromN(bmsg.pedersenPublic.n);
    this.Pedersen[from] = bmsg.pedersenPublic;
    this.vssPolynomials[from] = vssPolynomial;
    this.SchnorrCommitments[from] = bmsg.schnorrCommitment;
    this.ElGamalPublic[from] = bmsg.elGamalPublic;
  }

  public process(): KeygenRound3Output {
    let chainKey: bigint | null = this.inputForRound3.
      inputForRound2.inputRound1.previousChainKey;
    if (chainKey === null) {
      chainKey = 0n;
      for (const j of this.session.partyIds) {
        chainKey = chainKey ^ this.ChainKeys[j]; // XOR
      }
    }

    let rid = 0n;
    for (const j of this.session.partyIds) {
      rid = rid ^ this.RIDs[j]; // XOR
    }

    const hashWithRidAndPartyId = this.session.hasher.clone().updateMulti(
      [rid, this.session.selfId]
    );

    const modPriv: ZkModPrivate = {
      P: this.inputForRound3.inputForRound2.paillierSecret.p,
      Q: this.inputForRound3.inputForRound2.paillierSecret.q,
      Phi: this.inputForRound3.inputForRound2.paillierSecret.phi,
    };
    const modPub: ZkModPublic = {
      N: this.PaillierPublic[this.session.selfId].n,
    };
    const modProof = zkModCreateProof(modPriv, modPub, hashWithRidAndPartyId.clone());

    const prmPriv: ZkPrmPrivate = {
      Lambda: this.inputForRound3.inputForRound2.pedersenSecret,
      Phi: this.inputForRound3.inputForRound2.paillierSecret.phi,
      P: this.inputForRound3.inputForRound2.paillierSecret.p,
      Q: this.inputForRound3.inputForRound2.paillierSecret.q,
    };
    const prmPub: ZkPrmPublic = {
      Aux: this.Pedersen[this.session.selfId],
    };
    const prmProof = zkPrmCreateProof(prmPriv, prmPub, hashWithRidAndPartyId.clone());

    const broadcasts: Array<KeygenBroadcastForRound4> = [
      KeygenBroadcastForRound4.from({
        from: this.session.selfId,
        modProof,
        prmProof,
      }),
    ];

    const directMessages: Array<KeygenDirectMessageForRound4> = [];
    this.session.partyIds.forEach(j => {
      if (j === this.session.selfId) { return; }
      // for other PartyIds:

      const facPriv: ZkFacPrivate = {
        P: this.inputForRound3.inputForRound2.paillierSecret.p,
        Q: this.inputForRound3.inputForRound2.paillierSecret.q,
      };
      const facPub: ZkFacPublic = {
        N: this.PaillierPublic[this.session.selfId].n,
        Aux: this.Pedersen[j],
      };
      const facProof = zkFacCreateProof(facPriv, facPub, hashWithRidAndPartyId.clone());

      const { vssSecret } = this.inputForRound3.inputForRound2.inputRound1;
      const share = vssSecret.evaluate(partyIdToScalar(j));
      const { ciphertext: C } = this.PaillierPublic[j].encrypt(share);

      directMessages.push(KeygenDirectMessageForRound4.from({
        from: this.session.selfId,
        to: j,
        share: C,
        facProof,
      }));
    });

    this.session.hasher.update(rid);

    return {
      broadcasts,
      directMessages,
      inputForRound4: {
        inputForRound3: this.inputForRound3,
        RID: rid,
        ChainKey: chainKey,
        PedersenPublic: this.Pedersen,
        PaillierPublic: this.PaillierPublic,
        vssPolynomials: this.vssPolynomials,
        ElGamalPublic: this.ElGamalPublic,
        SchnorrCommitments: this.SchnorrCommitments,
      }
    };
  }
}
