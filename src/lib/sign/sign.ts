import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

import { PartyId } from "../keyConfig.js";

export type SignRequestJSON = {
  messageHex: string,
  signerIds: Array<string>,
};

export class SignRequest {
  public readonly message: Uint8Array;
  public readonly signerIds: Array<PartyId>;

  private constructor(message: Uint8Array, signerIds: Array<PartyId>) {
    this.message = message;
    this.signerIds = signerIds;
  }

  public static from({
    message,
    signerIds,
  }: {
    message: Uint8Array,
    signerIds: Array<PartyId>,
  }): SignRequest {
    const sr = new SignRequest(message, signerIds);
    Object.freeze(sr);
    return sr;
  }

  public static fromJSON(json: SignRequestJSON): SignRequest {
    return SignRequest.from({
      message: hexToBytes(json.messageHex),
      signerIds: json.signerIds,
    });
  }

  public toJSON(): SignRequestJSON {
    return {
      messageHex: bytesToHex(this.message),
      signerIds: this.signerIds,
    };
  }
};
