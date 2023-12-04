import { test } from 'node:test';
import assert from 'node:assert/strict';

import { bytesToHex } from '@noble/hashes/utils';
import { keccak_256 } from '@noble/hashes/sha3';
import * as ethers from 'ethers';

import { PartyId, PartySecretKeyConfig, getPublicPoint } from '../lib/keyConfig.js';
import { KeygenSession } from '../lib/keygen/KeygenSession.js';
import { KeygenRound1, KeygenRound1Output } from '../lib/keygen/KeygenRound1.js';
import { KeygenRound2, KeygenRound2Output } from '../lib/keygen/KeygenRound2.js';
import { KeygenRound3, KeygenRound3Output } from '../lib/keygen/KeygenRound3.js';
import { KeygenRound4, KeygenRound4Output } from '../lib/keygen/KeygenRound4.js';
import { KeygenRound5, KeygenRound5Output } from '../lib/keygen/KeygenRound5.js';
import { SignSession } from '../lib/sign/SignSession.js';
import { SignRequestSerialized, deserializeSignRequest } from '../lib/sign/sign.js';
import { SignPartyOutputRound1, SignerRound1 } from '../lib/sign/SignerRound1.js';
import { SignPartyOutputRound2, SignerRound2 } from '../lib/sign/SignerRound2.js';
import { SignPartyOutputRound3, SignerRound3 } from '../lib/sign/SignerRound3.js';
import { SignPartyOutputRound4, SignerRound4 } from '../lib/sign/SignerRound4.js';
import { SignPartyOutputRound5, SignerRound5 } from '../lib/sign/SignerRound5.js';
import { ethAddress, sigEthereum } from '../lib/eth.js';

test('keygen + sign', async () => {
  // Config
  const partyIds = ['a', 'b', 'c'];
  const threshold = 1; // Number of parties that could be missed out
  const signerIds = partyIds.slice(0, -threshold); // Taking minimum number of parties to sign
  const messageToSign = 'hello';
  const signRequestSerialized: SignRequestSerialized = {
    messageHex: bytesToHex(keccak_256(messageToSign)),
    signerIds,
  };
  const signRequest = deserializeSignRequest(signRequestSerialized);
  console.log('partyIds', partyIds);
  console.log('threshold', threshold);
  console.log('signerIds', signerIds);

  // KEYGEN
  // Init session
  console.log('keygen: init sessions');
  const keygenSessions: Record<PartyId, KeygenSession> = {};
  for (const partyId of partyIds) {
    keygenSessions[partyId] = new KeygenSession(partyId, partyIds, threshold);
  }

  // Keygen Round 1
  console.log('keygen: round 1');
  const keygenRounds1: Record<PartyId, KeygenRound1> = {};
  const keygenOutputs1: Record<PartyId, KeygenRound1Output> = {};
  for (const partyId of partyIds) {
    keygenRounds1[partyId] = new KeygenRound1(
      keygenSessions[partyId],
      keygenSessions[partyId].inputForRound1
    );
    keygenOutputs1[partyId] = await keygenRounds1[partyId].process();
  }

  // Keygen Round 2
  console.log('keygen: round 2');
  const allBroadcastsK1 = Object.entries(keygenOutputs1).flatMap(([_, output]) => output.broadcasts);
  const keygenRounds2: Record<PartyId, KeygenRound2> = {};
  const keygenOutputs2: Record<PartyId, KeygenRound2Output> = {};
  for (const partyId of partyIds) {
    keygenRounds2[partyId] = new KeygenRound2(
      keygenSessions[partyId],
      keygenOutputs1[partyId].inputForRound2
    );
    allBroadcastsK1.forEach((b) => keygenRounds2[partyId].handleBroadcastMessage(b));
    keygenOutputs2[partyId] = await keygenRounds2[partyId].process();
  }

  // Keygen Round 3
  console.log('keygen: round 3');
  const allBroadcastsK2 = Object.entries(keygenOutputs2).flatMap(([_, output]) => output.broadcasts);
  const keygenRounds3: Record<PartyId, KeygenRound3> = {};
  const keygenOutputs3: Record<PartyId, KeygenRound3Output> = {};
  for (const partyId of partyIds) {
    keygenRounds3[partyId] = new KeygenRound3(
      keygenSessions[partyId],
      keygenOutputs2[partyId].inputForRound3
    );
    allBroadcastsK2.forEach((b) => keygenRounds3[partyId].handleBroadcastMessage(b));
    keygenOutputs3[partyId] = await keygenRounds3[partyId].process();
  }

  // Keygen Round 4
  console.log('keygen: round 4');
  const allBroadcastsK3 = Object.entries(keygenOutputs3).flatMap(([_, output]) => output.broadcasts);
  const allMessagesK3 = Object.entries(keygenOutputs3).flatMap(([_, output]) => output.directMessages);
  const keygenRounds4: Record<PartyId, KeygenRound4> = {};
  const keygenOutputs4: Record<PartyId, KeygenRound4Output> = {};
  for (const partyId of partyIds) {
    keygenRounds4[partyId] = new KeygenRound4(
      keygenSessions[partyId],
      keygenOutputs3[partyId].inputForRound4
    );
    allBroadcastsK3.forEach((b) => keygenRounds4[partyId].handleBroadcastMessage(b));
    allMessagesK3.filter((m) => m.to === partyId).forEach((m) => keygenRounds4[partyId].handleDirectMessage(m));
    keygenOutputs4[partyId] = await keygenRounds4[partyId].process();
  }

  // Keygen Round 5
  console.log('keygen: round 5');
  const allBroadcastsK4 = Object.entries(keygenOutputs4).flatMap(([_, output]) => output.broadcasts);
  const keygenRounds5: Record<PartyId, KeygenRound5> = {};
  const keygenOutputs5: Record<PartyId, KeygenRound5Output> = {};
  for (const partyId of partyIds) {
    keygenRounds5[partyId] = new KeygenRound5(
      keygenSessions[partyId],
      keygenOutputs4[partyId].inputForRound5
    );
    allBroadcastsK4.forEach((b) => keygenRounds5[partyId].handleBroadcastMessage(b));
    keygenOutputs5[partyId] = await keygenRounds5[partyId].process();
  }

  // Compare outputs of keygen
  const outputRound5A = keygenOutputs5.a;
  for (const partyId of partyIds) {
    assert.deepEqual(
      outputRound5A.UpdatedConfig.publicPartyData,
      keygenOutputs5[partyId].UpdatedConfig.publicPartyData
    );
  }

  // SIGN
  // Config
  const partyConfigs: Record<PartyId, PartySecretKeyConfig> = {};
  for (const partyId of signerIds) {
    partyConfigs[partyId] = keygenOutputs5[partyId].UpdatedConfig;
  }

  // Init session
  console.log('sign: init sessions');
  const signSessions: Record<PartyId, SignSession> = {};
  for (const partyId of signerIds) {
    signSessions[partyId] = new SignSession(signRequest, partyConfigs[partyId]);
  }

  // Sign Round 1
  console.log('sign: round 1');
  const signersRound1: Record<PartyId, SignerRound1> = {};
  const signersRound1Outputs: Record<PartyId, SignPartyOutputRound1> = {};
  for (const partyId of signerIds) {
    signersRound1[partyId] = new SignerRound1(signSessions[partyId], signSessions[partyId].inputForRound1);
    signersRound1Outputs[partyId] = signersRound1[partyId].process();
  }

  // Sign Round 2
  console.log('sign: round 2');
  const allBroadcastsS1 = Object.entries(signersRound1Outputs).flatMap(([_, output]) => output.broadcasts);
  const allDirectMessagesS1 = Object.entries(signersRound1Outputs).flatMap(([_, output]) => output.messages);
  const signersRound2: Record<PartyId, SignerRound2> = {};
  const signersRound2Outputs: Record<PartyId, SignPartyOutputRound2> = {};
  for (const partyId of signerIds) {
    signersRound2[partyId] = new SignerRound2(signSessions[partyId], signersRound1Outputs[partyId].inputForRound2);
    allBroadcastsS1.forEach((b) => signersRound2[partyId].handleBroadcastMessage(b));
    allDirectMessagesS1.filter((m) => m.to === partyId).forEach((m) => signersRound2[partyId].handleDirectMessage(m));
    signersRound2Outputs[partyId] = signersRound2[partyId].process();
  }

  // Sign Round 3
  console.log('sign: round 3');
  const allBroadcastsS2 = Object.entries(signersRound2Outputs).flatMap(([_, output]) => output.broadcasts);
  const allDirectMessagesS2 = Object.entries(signersRound2Outputs).flatMap(([_, output]) => output.messages);
  const signersRound3: Record<PartyId, SignerRound3> = {};
  const signersRound3Outputs: Record<PartyId, SignPartyOutputRound3> = {};
  for (const partyId of signerIds) {
    signersRound3[partyId] = new SignerRound3(signSessions[partyId], signersRound2Outputs[partyId].inputForRound3);
    allBroadcastsS2.forEach((b) => signersRound3[partyId].handleBroadcastMessage(b));
    allDirectMessagesS2.filter((m) => m.to === partyId).forEach((m) => signersRound3[partyId].handleDirectMessage(m));
    signersRound3Outputs[partyId] = signersRound3[partyId].process();
  }

  // Sign Round 4
  console.log('sign: round 4');
  const allBroadcastsS3 = Object.entries(signersRound3Outputs).flatMap(([_, output]) => output.broadcasts);
  const allDirectMessagesS3 = Object.entries(signersRound3Outputs).flatMap(([_, output]) => output.messages);
  const signersRound4: Record<PartyId, SignerRound4> = {};
  const signersRound4Outputs: Record<PartyId, SignPartyOutputRound4> = {};
  for (const partyId of signerIds) {
    signersRound4[partyId] = new SignerRound4(signSessions[partyId], signersRound3Outputs[partyId].inputForRound4);
    allBroadcastsS3.forEach((b) => signersRound4[partyId].handleBroadcastMessage(b));
    allDirectMessagesS3.filter((m) => m.to === partyId).forEach((m) => signersRound4[partyId].handleDirectMessage(m));
    signersRound4Outputs[partyId] = signersRound4[partyId].process();
  }

  // Sign Round 5
  console.log('sign: round 5');
  const allBroadcastsS4 = Object.entries(signersRound4Outputs).flatMap(([_, output]) => output.broadcasts);
  const signersRound5: Record<PartyId, SignerRound5> = {};
  const signersRound5Outputs: Record<PartyId, SignPartyOutputRound5> = {};
  for (const partyId of signerIds) {
    signersRound5[partyId] = new SignerRound5(signSessions[partyId], signersRound4Outputs[partyId].inputForRound5);
    allBroadcastsS4.forEach((b) => signersRound5[partyId].handleBroadcastMessage(b));
    signersRound5Outputs[partyId] = signersRound5[partyId].process();
  }

  // Compare outputs of signing
  const round5outputA = signersRound5Outputs.a;
  for (const partyId of signerIds) {
    assert.deepEqual(round5outputA, signersRound5Outputs[partyId]);
  }

  const pubPoint = getPublicPoint(partyConfigs['a'].publicPartyData);
  const address = ethAddress(pubPoint);

  const ethSig = sigEthereum(round5outputA.signature.R, round5outputA.signature.S);

  const addressRec = ethers.recoverAddress(
    signRequest.message, '0x' + bytesToHex(ethSig)
  ).toLowerCase();

  assert.strictEqual(address, addressRec);
  console.log('sign: completes');
});
