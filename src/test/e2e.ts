import { test } from 'node:test';
import assert from 'node:assert/strict';

import * as ethers from 'ethers';

import { KeygenSession } from '../lib/keygen/KeygenSession.js';
import { KeygenRound1 } from '../lib/keygen/KeygenRound1.js';
import { KeygenRound2 } from '../lib/keygen/KeygenRound2.js';
import { KeygenRound3 } from '../lib/keygen/KeygenRound3.js';
import { KeygenRound4 } from '../lib/keygen/KeygenRound4.js';
import { KeygenRound5 } from '../lib/keygen/KeygenRound5.js';
import { SignSession } from '../lib/sign/SignSession.js';
import { SignRequestSerialized, deserializeSignRequest } from '../lib/sign/sign.js';
import { bytesToHex } from '@noble/hashes/utils';
import { keccak_256 } from '@noble/hashes/sha3';
import { SignerRound1 } from '../lib/sign/SignerRound1.js';
import { SignerRound2 } from '../lib/sign/SignerRound2.js';
import { SignerRound3 } from '../lib/sign/SignerRound3.js';
import { SignerRound4 } from '../lib/sign/SignerRound4.js';
import { SignerRound5 } from '../lib/sign/SignerRound5.js';
import { getPublicPoint } from '../lib/keyConfig.js';
import { ethAddress, sigEthereum } from '../lib/eth.js';



test('keygen 2/3', async () => {
  const partyIds = ['a', 'b', 'c'];
  const threshold = 1; // 2/3

  // KEYGEN
  const kGsessionA = new KeygenSession('a', partyIds, threshold);
  const kGsessionB = new KeygenSession('b', partyIds, threshold);
  const kGsessionC = new KeygenSession('c', partyIds, threshold);

  const keygenRound1A = new KeygenRound1(kGsessionA, kGsessionA.inputForRound1);
  const outputRound1A = await keygenRound1A.process();
  const keygenRound1B = new KeygenRound1(kGsessionB, kGsessionB.inputForRound1);
  const outputRound1B = await keygenRound1B.process();
  const keygenRound1C = new KeygenRound1(kGsessionC, kGsessionC.inputForRound1);
  const outputRound1C = await keygenRound1C.process();

  const allBroadcastsK1 = [
    ...outputRound1A.broadcasts,
    ...outputRound1B.broadcasts,
    ...outputRound1C.broadcasts,
  ];
  const keygenRound2A = new KeygenRound2(kGsessionA, outputRound1A.inputForRound2);
  allBroadcastsK1.forEach((b) => keygenRound2A.handleBroadcastMessage(b));
  const outputRound2A = keygenRound2A.process();
  const keygenRound2B = new KeygenRound2(kGsessionB, outputRound1B.inputForRound2);
  allBroadcastsK1.forEach((b) => keygenRound2B.handleBroadcastMessage(b));
  const outputRound2B = keygenRound2B.process();
  const keygenRound2C = new KeygenRound2(kGsessionC, outputRound1C.inputForRound2);
  allBroadcastsK1.forEach((b) => keygenRound2C.handleBroadcastMessage(b));
  const outputRound2C = keygenRound2C.process();

  const allBroadcastsK2 = [
    ...outputRound2A.broadcasts,
    ...outputRound2B.broadcasts,
    ...outputRound2C.broadcasts,
  ];
  const keygenRound3A = new KeygenRound3(kGsessionA, outputRound2A.inputForRound3);
  allBroadcastsK2.forEach((b) => keygenRound3A.handleBroadcastMessage(b));
  const outputRound3A = keygenRound3A.process();
  const keygenRound3B = new KeygenRound3(kGsessionB, outputRound2B.inputForRound3);
  allBroadcastsK2.forEach((b) => keygenRound3B.handleBroadcastMessage(b));
  const outputRound3B = keygenRound3B.process();
  const keygenRound3C = new KeygenRound3(kGsessionC, outputRound2C.inputForRound3);
  allBroadcastsK2.forEach((b) => keygenRound3C.handleBroadcastMessage(b));
  const outputRound3C = keygenRound3C.process();

  const allBroadcastsK3 = [
    ...outputRound3A.broadcasts,
    ...outputRound3B.broadcasts,
    ...outputRound3C.broadcasts,
  ];
  const allMessagesK3 = [
    ...outputRound3A.directMessages,
    ...outputRound3B.directMessages,
    ...outputRound3C.directMessages,
  ];

  const keygenRound4A = new KeygenRound4(kGsessionA, outputRound3A.inputForRound4);
  allBroadcastsK3.forEach((b) => keygenRound4A.handleBroadcastMessage(b));
  const messagesForA = allMessagesK3.filter((m) => m.to === 'a');
  messagesForA.forEach((m) => keygenRound4A.handleDirectMessage(m));
  const outputRound4A = keygenRound4A.process();
  const keygenRound4B = new KeygenRound4(kGsessionB, outputRound3B.inputForRound4);
  allBroadcastsK3.forEach((b) => keygenRound4B.handleBroadcastMessage(b));
  const messagesForB = allMessagesK3.filter((m) => m.to === 'b');
  messagesForB.forEach((m) => keygenRound4B.handleDirectMessage(m));
  const outputRound4B = keygenRound4B.process();
  const keygenRound4C = new KeygenRound4(kGsessionC, outputRound3C.inputForRound4);
  allBroadcastsK3.forEach((b) => keygenRound4C.handleBroadcastMessage(b));
  const messagesForC = allMessagesK3.filter((m) => m.to === 'c');
  messagesForC.forEach((m) => keygenRound4C.handleDirectMessage(m));
  const outputRound4C = keygenRound4C.process();


  const allBroadcastsK4 = [
    ...outputRound4A.broadcasts,
    ...outputRound4B.broadcasts,
    ...outputRound4C.broadcasts,
  ];
  const keygenRound5A = new KeygenRound5(kGsessionA, outputRound4A.inputForRound5);
  allBroadcastsK4.forEach((b) => keygenRound5A.handleBroadcastMessage(b));
  const outputRound5A = keygenRound5A.process();
  const keygenRound5B = new KeygenRound5(kGsessionB, outputRound4B.inputForRound5);
  allBroadcastsK4.forEach((b) => keygenRound5B.handleBroadcastMessage(b));
  const outputRound5B = keygenRound5B.process();
  const keygenRound5C = new KeygenRound5(kGsessionC, outputRound4C.inputForRound5);
  allBroadcastsK4.forEach((b) => keygenRound5C.handleBroadcastMessage(b));
  const outputRound5C = keygenRound5C.process();

  assert.deepEqual(
    outputRound5A.UpdatedConfig.publicPartyData,
    outputRound5B.UpdatedConfig.publicPartyData,
  );
  assert.deepEqual(
    outputRound5A.UpdatedConfig.publicPartyData,
    outputRound5C.UpdatedConfig.publicPartyData
  );

  // SIGN
  const messageToSign = 'hello';
  const signRequestSerialized: SignRequestSerialized = {
    messageHex: bytesToHex(keccak_256(messageToSign)),
    signerIds: ['a', 'b', 'c'],
  };
  const signRequest = deserializeSignRequest(signRequestSerialized);

  const partyConfigA = outputRound5A.UpdatedConfig;
  const partyConfigB = outputRound5B.UpdatedConfig;
  const partyConfigC = outputRound5C.UpdatedConfig;

  const sessionA = new SignSession(signRequest, partyConfigA);
  const inputForRound1A = sessionA.inputForRound1;
  const sessionB = new SignSession(signRequest, partyConfigB);
  const inputForRound1B = sessionB.inputForRound1;
  const sessionC = new SignSession(signRequest, partyConfigC);
  const inputForRound1C = sessionC.inputForRound1;

  const signerRound1A = new SignerRound1(sessionA, inputForRound1A);
  const round1outputA = signerRound1A.process();
  const signerRound1B = new SignerRound1(sessionB, inputForRound1B);
  const round1outputB = signerRound1B.process();
  const signerRound1C = new SignerRound1(sessionC, inputForRound1C);
  const round1outputC = signerRound1C.process();

  const allBroadcastsS1 = [
    ...round1outputA.broadcasts,
    ...round1outputB.broadcasts,
    ...round1outputC.broadcasts,
  ];
  const s1directMessagesToA = [
    ...round1outputB.messages.filter((m) => m.to === 'a'),
    ...round1outputC.messages.filter((m) => m.to === 'a'),
  ];
  const s1directMessagesToB = [
    ...round1outputA.messages.filter((m) => m.to === 'b'),
    ...round1outputC.messages.filter((m) => m.to === 'b'),
  ];
  const s1directMessagesToC = [
    ...round1outputA.messages.filter((m) => m.to === 'c'),
    ...round1outputB.messages.filter((m) => m.to === 'c'),
  ];
  const signerRound2A = new SignerRound2(sessionA, round1outputA.inputForRound2);
  allBroadcastsS1.forEach((b) => signerRound2A.handleBroadcastMessage(b));
  s1directMessagesToA.forEach((m) => signerRound2A.handleDirectMessage(m));
  const round2outputA = signerRound2A.process();
  const signerRound2B = new SignerRound2(sessionB, round1outputB.inputForRound2);
  allBroadcastsS1.forEach((b) => signerRound2B.handleBroadcastMessage(b));
  s1directMessagesToB.forEach((m) => signerRound2B.handleDirectMessage(m));
  const round2outputB = signerRound2B.process();
  const signerRound2C = new SignerRound2(sessionC, round1outputC.inputForRound2);
  allBroadcastsS1.forEach((b) => signerRound2C.handleBroadcastMessage(b));
  s1directMessagesToC.forEach((m) => signerRound2C.handleDirectMessage(m));
  const round2outputC = signerRound2C.process();

  const allBroadcastsS2 = [
    ...round2outputA.broadcasts,
    ...round2outputB.broadcasts,
    ...round2outputC.broadcasts,
  ];
  const s2directMessagesToA = [
    ...round2outputB.messages.filter((m) => m.to === 'a'),
    ...round2outputC.messages.filter((m) => m.to === 'a'),
  ];
  const s2directMessagesToB = [
    ...round2outputA.messages.filter((m) => m.to === 'b'),
    ...round2outputC.messages.filter((m) => m.to === 'b'),
  ];
  const s2directMessagesToC = [
    ...round2outputA.messages.filter((m) => m.to === 'c'),
    ...round2outputB.messages.filter((m) => m.to === 'c'),
  ];
  const signerRound3A = new SignerRound3(sessionA, round2outputA.inputForRound3);
  allBroadcastsS2.forEach((b) => signerRound3A.handleBroadcastMessage(b));
  s2directMessagesToA.forEach((m) => signerRound3A.handleDirectMessage(m));
  const round3outputA = signerRound3A.process();
  const signerRound3B = new SignerRound3(sessionB, round2outputB.inputForRound3);
  allBroadcastsS2.forEach((b) => signerRound3B.handleBroadcastMessage(b));
  s2directMessagesToB.forEach((m) => signerRound3B.handleDirectMessage(m));
  const round3outputB = signerRound3B.process();
  const signerRound3C = new SignerRound3(sessionC, round2outputC.inputForRound3);
  allBroadcastsS2.forEach((b) => signerRound3C.handleBroadcastMessage(b));
  s2directMessagesToC.forEach((m) => signerRound3C.handleDirectMessage(m));
  const round3outputC = signerRound3C.process();

  const allBroadcastsS3 = [
    ...round3outputA.broadcasts,
    ...round3outputB.broadcasts,
    ...round3outputC.broadcasts,
  ];
  const s3directMessagesToA = [
    ...round3outputB.messages.filter((m) => m.to === 'a'),
    ...round3outputC.messages.filter((m) => m.to === 'a'),
  ];
  const s3directMessagesToB = [
    ...round3outputA.messages.filter((m) => m.to === 'b'),
    ...round3outputC.messages.filter((m) => m.to === 'b'),
  ];
  const s3directMessagesToC = [
    ...round3outputA.messages.filter((m) => m.to === 'c'),
    ...round3outputB.messages.filter((m) => m.to === 'c'),
  ];
  const signerRound4A = new SignerRound4(sessionA, round3outputA.inputForRound4);
  allBroadcastsS3.forEach((b) => signerRound4A.handleBroadcastMessage(b));
  s3directMessagesToA.forEach((m) => signerRound4A.handleDirectMessage(m));
  const round4outputA = signerRound4A.process();
  const signerRound4B = new SignerRound4(sessionB, round3outputB.inputForRound4);
  allBroadcastsS3.forEach((b) => signerRound4B.handleBroadcastMessage(b));
  s3directMessagesToB.forEach((m) => signerRound4B.handleDirectMessage(m));
  const round4outputB = signerRound4B.process();
  const signerRound4C = new SignerRound4(sessionC, round3outputC.inputForRound4);
  allBroadcastsS3.forEach((b) => signerRound4C.handleBroadcastMessage(b));
  s3directMessagesToC.forEach((m) => signerRound4C.handleDirectMessage(m));
  const round4outputC = signerRound4C.process();

  const allBroadcastsS4 = [
    ...round4outputA.broadcasts,
    ...round4outputB.broadcasts,
    ...round4outputC.broadcasts,
  ];
  const signerRound5A = new SignerRound5(sessionA, round4outputA.inputForRound5);
  allBroadcastsS4.forEach((b) => signerRound5A.handleBroadcastMessage(b));
  const round5outputA = signerRound5A.process();
  const signerRound5B = new SignerRound5(sessionB, round4outputB.inputForRound5);
  allBroadcastsS4.forEach((b) => signerRound5B.handleBroadcastMessage(b));
  const round5outputB = signerRound5B.process();
  const signerRound5C = new SignerRound5(sessionC, round4outputC.inputForRound5);
  allBroadcastsS4.forEach((b) => signerRound5C.handleBroadcastMessage(b));
  const round5outputC = signerRound5C.process();

  assert.deepEqual(round5outputA, round5outputB);
  assert.deepEqual(round5outputB, round5outputC);

  const pubPoint = getPublicPoint(partyConfigA.publicPartyData);
  const address = ethAddress(pubPoint);

  const ethSig = sigEthereum(round5outputA.signature.R, round5outputA.signature.S);

  const addressRec = ethers.recoverAddress(
    signRequest.message, '0x' + bytesToHex(ethSig)
  ).toLowerCase();

  assert.strictEqual(address, addressRec);
});
