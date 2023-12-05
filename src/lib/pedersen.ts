import { gcd, modPow, modMultiply } from "bigint-crypto-utils";

import { Hashable, IngestableBasic } from "./Hasher.js";
import { ToJSONable } from './serde.js'

export type PedersenParametersJSON = {
  nHex: string;
  sHex: string;
  tHex: string;
};

export class PedersenParams implements Hashable, ToJSONable {
  private _n: bigint;
  private _s: bigint;
  private _t: bigint;

  private constructor(n: bigint, s: bigint, t: bigint) {
    this._n = n;
    this._s = s;
    this._t = t;
  }

  public get n(): bigint { return this._n; }
  public get s(): bigint { return this._s; }
  public get t(): bigint { return this._t; }

  public static from(n: bigint, s: bigint, t: bigint): PedersenParams {
    const pp = new PedersenParams(n, s, t);
    Object.freeze(pp);
    return pp;
  }

  public toJSON(): PedersenParametersJSON {
    return {
      nHex: this._n.toString(16),
      sHex: this._s.toString(16),
      tHex: this._t.toString(16),
    };
  }

  public static fromJSON(paramsJson: PedersenParametersJSON): PedersenParams {
    const n = BigInt('0x' + paramsJson.nHex);
    const s = BigInt('0x' + paramsJson.sHex);
    const t = BigInt('0x' + paramsJson.tHex);
    return new PedersenParams(n, s, t);
  }

  public hashable(): IngestableBasic[] {
    return [this._n, this._s, this._t];
  }

  public static validateParams(n: bigint, s: bigint, t: bigint): void {
    if (n <= 0n) {
      throw new Error('INVALID_PEDERSEN_PARAMETERS: n must be positive');
    }
    if (s <= 0n) {
      throw new Error('INVALID_PEDERSEN_PARAMETERS: s must be positive');
    }
    if (t <= 0n) {
      throw new Error('INVALID_PEDERSEN_PARAMETERS: t must be positive');
    }
    if (s >= n) {
      throw new Error('INVALID_PEDERSEN_PARAMETERS: s must be less than n');
    }
    if (t >= n) {
      throw new Error('INVALID_PEDERSEN_PARAMETERS: t must be less than n');
    }
    if (s === t) {
      throw new Error('INVALID_PEDERSEN_PARAMETERS: s and t must be different');
    }
    if (gcd(s, n) !== 1n) {
      throw new Error('INVALID_PEDERSEN_PARAMETERS: s must be coprime to n');
    }
    if (gcd(t, n) !== 1n) {
      throw new Error('INVALID_PEDERSEN_PARAMETERS: t must be coprime to n');
    }
  }

  public validate(): void {
    PedersenParams.validateParams(this._n, this._s, this._t);
  }

  public commit(x: bigint, y: bigint): bigint {
    const sx = modPow(this._s, x, this._n);
    const ty = modPow(this._t, y, this._n);
    return modMultiply([sx, ty], this._n);
  }

  public verify(a: bigint, b: bigint, e: bigint, S: bigint, T: bigint): boolean {
    try {
      PedersenParams.validateParams(this.n, S, T);
    } catch (error) {
      // TODO: check error type
      return false;
    }

    const sa = modPow(this._s, a, this._n);
    const tb = modPow(this._t, b, this._n);
    const lhs = modMultiply([sa, tb], this._n);

    const te = modPow(T, e, this._n);
    const rhs = modMultiply([te, S], this._n);
    return lhs === rhs;
  }
}
