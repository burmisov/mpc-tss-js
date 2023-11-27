import { ProjectivePoint } from "./common.types.js";

// Identity point? TODO: check if this is the right way to do it
export const isIdentity = (point: ProjectivePoint) => {
  return (point.px === 0n && point.py === 0n) || point.pz === 0n;
};
