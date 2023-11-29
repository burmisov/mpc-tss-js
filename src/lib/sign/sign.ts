import { hexToBytes } from '@noble/hashes/utils';

import { PartyId } from "../keyConfig.js";

export type SignRequest = {
  message: Uint8Array,
  signerIds: Array<PartyId>,
};

export type SignRequestSerialized = {
  messageHex: string,
  signerIds: Array<string>,
};

export const deserializeSignRequest = (
  serialized: SignRequestSerialized
): SignRequest => {
  return {
    message: hexToBytes(serialized.messageHex),
    signerIds: serialized.signerIds,
  };
};
