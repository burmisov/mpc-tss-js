import { secp256k1 } from '@noble/curves/secp256k1';

// Extract some types from @noble/curves because they're not exported
export type AffinePoint = Parameters<typeof secp256k1.ProjectivePoint.fromAffine>[0];
export type ProjectivePoint = ReturnType<typeof secp256k1.ProjectivePoint.fromAffine>;

export type AffinePointJSON = {
  xHex: string,
  yHex: string,
}
