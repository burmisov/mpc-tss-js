import { secp256k1 } from "@noble/curves/secp256k1";

import { AffinePoint, ProjectivePoint } from "../common.types.js";
import { Polynomial } from "./polynomial.js";
import Fn from "../Fn.js";
import { Hashable, IngestableBasic } from "../Hasher.js";

export class Exponent implements Hashable {
  public isConstant: boolean;
  public coefficients: Array<ProjectivePoint>;

  private constructor(isConstant: boolean, coefficients: Array<ProjectivePoint>) {
    this.isConstant = isConstant;
    this.coefficients = coefficients;
  }

  hashable(): IngestableBasic[] {
    return this.coefficients.flatMap(a => {
      const p = a.toAffine();
      return [p.x, p.y];
    });
  }

  static fromPoly(poly: Polynomial): Exponent {
    const isConstant = poly.coefficients[0] === 0n;
    const coefficients = [];
    for (let i = 0; i < poly.coefficients.length; i++) {
      if (isConstant && i === 0) {
        // skip
      } else {
        coefficients.push(secp256k1.ProjectivePoint.BASE.multiply(poly.coefficients[i]));
      }
    }
    const exp = new Exponent(isConstant, coefficients);
    Object.freeze(exp);
    return exp;
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

  public degree(): number {
    if (this.isConstant) {
      return this.coefficients.length;
    }
    return this.coefficients.length - 1;
  }

  public add(other: Exponent): void {
    if (this.coefficients.length !== other.coefficients.length) {
      throw new Error("q is not the same length as p");
    }

    if (this.isConstant !== other.isConstant) {
      throw new Error("p and q differ in 'IsConstant'");
    }

    for (let i = 0; i < this.coefficients.length; i += 1) {
      this.coefficients[i] = this.coefficients[i].add(other.coefficients[i]);
    }
  }

  static sum(polys: Array<Exponent>): Exponent {
    const summed = polys[0].copy();
    for (let i = 1; i < polys.length; i++) {
      summed.add(polys[i]);
    }
    return summed;
  }

  public copy(): Exponent {
    const copyExp = new Exponent(this.isConstant, this.coefficients.slice());
    Object.freeze(copyExp);
    return copyExp;
  }

  // TODO: more methods?
}
