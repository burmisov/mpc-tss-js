import { secp256k1 } from "@noble/curves/secp256k1";

import { AffinePoint, ProjectivePoint } from "../common.types.js";
import { Polynomial } from "./polynomial.js";
import Fn from "../Fn.js";

export class Exponent {
  public isConstant: boolean;
  public coefficients: Array<ProjectivePoint>;

  constructor(isConstant: boolean, coefficients: Array<ProjectivePoint>) {
    this.isConstant = isConstant;
    this.coefficients = coefficients;
  }

  static new(poly: Polynomial): Exponent {
    const isConstant = poly.coefficients[0] === 0n;
    const coefficients = [];
    for (let i = 0; i < poly.coefficients.length; i++) {
      if (isConstant && i === 0) {
        // skip
      } else {
        coefficients.push(secp256k1.ProjectivePoint.BASE.multiply(poly.coefficients[i]));
      }
    }
    return new Exponent(isConstant, coefficients);
  }

  public evaluate(x: bigint): AffinePoint {
    let result = secp256k1.ProjectivePoint.ZERO;
    for (let i = this.coefficients.length - 1; i >= 0; i--) {
      result = result.multiply(x).add(this.coefficients[i]);
    }
    if (this.isConstant) {
      result = result.multiply(x);
    }
    return result.toAffine();
  }

  public evaluateClassic(x: bigint): AffinePoint {
    let tmp = secp256k1.ProjectivePoint.ZERO;
    let xPower = 1n;
    let result = secp256k1.ProjectivePoint.ZERO;

    if (this.isConstant) {
      xPower = Fn.mul(xPower, x); // x
    }

    for (let i = 0; i < this.coefficients.length; i++) {
      tmp = this.coefficients[i].multiply(xPower); // [xⁱ]Aᵢ
      result = result.add(tmp); // result += [xⁱ]Aᵢ
      xPower = Fn.mul(xPower, x); // x = xⁱ⁺¹
    }

    return result.toAffine();
  }

  // TODO: more methods
}
