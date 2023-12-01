import { randBetween } from "bigint-crypto-utils";
import { partyIdToScalar } from "../keyConfig.js";
import {
  PaillierSecretKey, paillierGeneratePedersen, paillierSecretKeyFromPrimes,
  randomPaillierPrimes, validatePaillierPrime,
} from "../paillier.js";
import { Exponent } from "../polynomial/exponent.js";
import { Polynomial } from "../polynomial/polynomial.js";
import { sampleScalarPointPair } from "../sample.js";
import { zkSchCreateRandomness } from "../zk/zksch.js";
import { KeygenSession } from "./KeygenSession.js";
import { KeygenBroadcastForRound2, KeygenInputForRound2 } from "./KeygenRound2.js";

export type KeygenInputForRound1 = {
  vssSecret: Polynomial;
  precomputedPaillierPrimes?: {
    p: bigint;
    q: bigint;
  };

  // TODO: these are for refresh? not implemented yet
  previousSecretECDSA: null,
  previousPublicSharesECDSA: null,
  previousChainKey: null,
};

export type KeygenRound1Output = {
  broadcasts: Array<KeygenBroadcastForRound2>,
  inputForRound2: KeygenInputForRound2,
};

export class KeygenRound1 {
  public session: KeygenSession;
  private input: KeygenInputForRound1

  constructor(session: KeygenSession, input: KeygenInputForRound1) {
    this.session = session;
    this.input = input;
  }

  public async process(): Promise<KeygenRound1Output> {
    let paillierSecret: PaillierSecretKey;
    if (this.input.precomputedPaillierPrimes) {
      const { p, q } = this.input.precomputedPaillierPrimes;
      await validatePaillierPrime(p);
      await validatePaillierPrime(q);
      paillierSecret = paillierSecretKeyFromPrimes(p, q);
    } else {
      const { p, q } = await randomPaillierPrimes();
      paillierSecret = paillierSecretKeyFromPrimes(p, q);
    }

    const selfPaillierPublic = paillierSecret.publicKey;
    const {
      pedersen: selfPedersenPublic,
      lambda: pedersenSecret,
    } = paillierGeneratePedersen(paillierSecret);

    const [elGamalSecret, elGamalPublic] = sampleScalarPointPair();

    const selfShare = this.session.inputForRound1.vssSecret.evaluate(
      partyIdToScalar(this.session.selfId),
    );

    const selfVSSpolynomial = Exponent.new(this.session.inputForRound1.vssSecret);

    const schnorrRand = zkSchCreateRandomness();

    const selfRID = randBetween(2n ** 256n);
    const chainKey = randBetween(2n ** 256n);

    const {
      commitment: selfCommitment, decommitment,
    } = this.session.cloneHashForId(this.session.selfId).commit([
      selfRID,
      chainKey,
      selfVSSpolynomial,
      schnorrRand.commitment.C,
      elGamalPublic,
      selfPedersenPublic,
    ]);

    const broadcasts: Array<KeygenBroadcastForRound2> = [{
      from: this.session.selfId,
      commitment: selfCommitment,
    }];

    return {
      broadcasts,
      inputForRound2: {
        inputRound1: this.input,
        selfVSSpolynomial,
        selfCommitment,
        selfRID,
        chainKey,
        selfShare,
        elGamalPublic,
        selfPaillierPublic,
        selfPedersenPublic,
        elGamalSecret,
        paillierSecret,
        pedersenSecret,
        schnorrRand,
        decommitment,
      }
    };
  }
}
