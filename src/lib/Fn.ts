import { modAdd, modInv, modMultiply, modPow } from 'bigint-crypto-utils';
import { secp256k1 } from "@noble/curves/secp256k1";

export default class Fn {
  static N = secp256k1.CURVE.n;

  static mod(x: bigint): bigint {
    // TODO
    return modAdd([x, 0], Fn.N);
  }

  static mul(lhs: bigint, rhs: bigint): bigint {
    return modMultiply([lhs, rhs], Fn.N);
  }

  static add(lhs: bigint, rhs: bigint): bigint {
    return modAdd([lhs, rhs], Fn.N);
  }

  static sub(lhs: bigint, rhs: bigint): bigint {
    return modAdd([lhs, Fn.N - rhs], Fn.N);
  }

  static inv(x: bigint): bigint {
    return modInv(x, Fn.N);
  }

  static div(lhs: bigint, rhs: bigint): bigint {
    return modMultiply([lhs, Fn.inv(rhs)], Fn.N);
  }

  static pow(x: bigint, e: bigint): bigint {
    return modPow(x, e, Fn.N);
  }
}
