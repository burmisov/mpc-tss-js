import Fn from "../Fn.js";
import { sampleScalar } from "../sample.js";

export class Polynomial {
  private coefficients: Array<bigint>;

  constructor(degree: number, constant: bigint = 0n) {
    this.coefficients = [];
    this.coefficients.push(constant);
    for (let i = 1; i < degree; i++) {
      this.coefficients.push(sampleScalar());
    }
  }

  static new(degree: number, constant: bigint = 0n) {
    return new Polynomial(degree, constant);
  }

  static fromCoefficients(coefficients: Array<bigint>) {
    const poly = new Polynomial(0);
    poly.coefficients = coefficients.slice();
    return poly;
  }

  public evaluate(index: bigint): bigint {
    if (index === 0n) {
      throw new Error("attempt to leak secret");
    }

    let result = 0n;
    for (let i = this.coefficients.length - 1; i >= 0; i--) {
      // bₙ₋₁ = bₙ * x + aₙ₋₁
      result = Fn.add(Fn.mul(result, index), this.coefficients[i]);
    }
    return result;
  }

  public degree(): number {
    return this.coefficients.length - 1;
  }

  public constant(): bigint {
    return this.coefficients[0];
  }
}
