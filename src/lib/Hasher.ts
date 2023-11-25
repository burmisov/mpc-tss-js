import { bytesToNumberBE } from "@noble/curves/abstract/utils";
import { blake3 } from "@noble/hashes/blake3";
import { Input, hexToBytes } from "@noble/hashes/utils";
import { ProjectivePoint, AffinePoint } from "./common.types.js";
import { PaillierPublicKey } from "./paillier.js";
import { PedersenParameters } from "./pedersen.js";

type IngestableBasic = Uint8Array | string | bigint;
type Ingestable = IngestableBasic | ProjectivePoint | AffinePoint |
  PaillierPublicKey | PedersenParameters;

export class Hasher {
  private hash: ReturnType<typeof blake3.create>;
  private used: boolean = false;

  constructor() {
    this.hash = blake3.create({}); // TODO: pass params?
  }

  public static create(): Hasher {
    return new Hasher();
  }

  private checkUsed() {
    if (this.used) {
      throw new Error('Hasher already used');
    }
  }

  public digestBytes(): Uint8Array {
    this.checkUsed();
    this.used = true;
    return this.hash.digest();
  }

  public digestBigint(): bigint {
    this.checkUsed();
    this.used = true;
    return bytesToNumberBE(this.hash.digest());
  }

  private updateBasic(data: IngestableBasic): Hasher {
    this.checkUsed();
    let buf: Input;
    if (data instanceof Uint8Array) {
      buf = data;
    } else if (typeof data === 'string') {
      buf = data;
    } else if (typeof data === 'bigint') {
      let hex = data.toString(16);
      if (hex.length % 2 === 1) {
        hex = `0${hex}`;
      }
      buf = hexToBytes(hex);
    } else {
      throw new Error('Unsupported data type', data);
    }
    this.hash.update(buf);
    return this;
  }

  // TODO: make identifiable objects instead?..
  public update(data: Ingestable): Hasher {
    this.checkUsed();
    let buf: Array<IngestableBasic> = [];
    if (
      data instanceof Uint8Array ||
      typeof data === 'string' ||
      typeof data === 'bigint'
    ) {
      buf.push(data);
    } else if (typeof (data as PaillierPublicKey).n === 'bigint' &&
      typeof (data as PaillierPublicKey).nSquared === 'bigint' &&
      typeof (data as PaillierPublicKey).nPlusOne === 'bigint' &&
      Object.keys(data).length === 3
    ) {
      buf.push((data as PaillierPublicKey).n);
      buf.push((data as PaillierPublicKey).nSquared);
      buf.push((data as PaillierPublicKey).nPlusOne);
    } else if (
      typeof (data as PedersenParameters).n === 'bigint' &&
      typeof (data as PedersenParameters).s === 'bigint' &&
      typeof (data as PedersenParameters).t === 'bigint' &&
      Object.keys(data).length === 3
    ) {
      buf.push((data as PedersenParameters).n);
      buf.push((data as PedersenParameters).s);
      buf.push((data as PedersenParameters).t);
    } else if (
      typeof (data as AffinePoint).x === 'bigint' &&
      typeof (data as AffinePoint).y === 'bigint'
    ) {
      if (typeof (data as ProjectivePoint).toRawBytes === 'function') {
        buf.push((data as ProjectivePoint).toRawBytes());
      } else {
        buf.push((data as AffinePoint).x);
        buf.push((data as AffinePoint).y);
      }
    } else {
      throw new Error(`Unsupported data type: ${data}`);
    }
    for (let i = 0; i < buf.length; i += 1) {
      this.updateBasic(buf[i]);
    }
    return this;
  }

  public updateMulti(data: Array<Ingestable>): Hasher {
    this.checkUsed();
    for (let i = 0; i < data.length; i += 1) {
      this.update(data[i]);
    }
    return this;
  }
}