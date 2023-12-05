import { describe, test } from 'node:test';
import assert from 'node:assert/strict';

import * as ethers from 'ethers';

import { KeygenSession } from './KeygenSession.js';
import { KeygenRound1, KeygenRound1Output } from './KeygenRound1.js';
import { KeygenBroadcastForRound2, KeygenRound2, KeygenRound2Output } from './KeygenRound2.js';
import { KeygenBroadcastForRound3, KeygenRound3, KeygenRound3Output } from './KeygenRound3.js';
import { KeygenBroadcastForRound4, KeygenDirectMessageForRound4, KeygenRound4, KeygenRound4Output } from './KeygenRound4.js';
import { KeygenBroadcastForRound5, KeygenRound5, KeygenRound5Output } from './KeygenRound5.js';
import { ethAddress } from '../eth.js';
import { Hasher } from '../Hasher.js';

const precomputedPaillierPrimesA = {
  p: 140656066935617068498146945231934875455216373658357415502745428687235261656648638287551719750772170167072660618746434922467026175316328679021082239834872641463481202598538804109033672325604594242999482643715131298123781048438272500363100287151576822437239577277536933950267625817888142008490020035657029276407n,
  q: 175437726479818986625224700860380920063101111865374554740519436736586455912956005968158447930382949780886369408190562582756101804782170061689786605035300744632482593570950291647513234434906219657068892385520913477200820946242503153623041776816739567937245171318575515185901118752529992399233786355959816486303n,
};
const precomputedPaillierPrimesB = {
  p: 137312309442365190985453965256251210460603159730204725844118916677462452771994940718304282770965138672535932808453134415361000450811737515111571482496009541277257706682425555911096230514145252653294455628468041511731994420074667966069448372869440435488242560999933450296602755952859656929998948219035065898667n,
  q: 143281264892183745474757670678877006167442496950492417343173058614567659544203501581302031822514190565147418599504646809324272315060597775090263252486159812228650729480319543583110287898306177134050155423348930741512343464796304140221523128443625401783754211349019345572066231912668570174135585677933034479559n,
};
const precomputedPaillierPrimesC = {
  p: 156163980637379337582085166508026613650620853422139282222958322433030968938851006607204056485610679309183651453513647144237837663029565322727163125052105921988109851945711195893550033894618911331558609040313260519930772467786359266963363146075360035101620140126149494261912647604217968532411875952842328078747n,
  q: 140880508068848076223357419249431051232731440044527820091184456267281931249379218390370105137932724533395294994976453903711432690103142884714548045498423840693730950393865846602334428949043972330130098632240078495263471643195666327383140483980663105182464991272806143418463958797359483550572413188948720360607n,
};

describe('keygen 2/3', async () => {
  const partyIds = ['a', 'b', 'c'];
  const threshold = 1; // 2/3

  let sessionA: KeygenSession;
  let outputRound1A: KeygenRound1Output;
  let outputRound2A: KeygenRound2Output;
  let outputRound3A: KeygenRound3Output;
  let outputRound4A: KeygenRound4Output;
  let outputRound5A: KeygenRound5Output;

  let sessionB: KeygenSession;
  let outputRound1B: KeygenRound1Output;
  let outputRound2B: KeygenRound2Output;
  let outputRound3B: KeygenRound3Output;
  let outputRound4B: KeygenRound4Output;
  let outputRound5B: KeygenRound5Output;

  let sessionC: KeygenSession;
  let outputRound1C: KeygenRound1Output;
  let outputRound2C: KeygenRound2Output;
  let outputRound3C: KeygenRound3Output;
  let outputRound4C: KeygenRound4Output;
  let outputRound5C: KeygenRound5Output;

  test('initiate session', async () => {
    // Use precomputed primes to speed up tests
    sessionA = new KeygenSession('a', partyIds, threshold, precomputedPaillierPrimesA);
    sessionB = new KeygenSession('b', partyIds, threshold, precomputedPaillierPrimesB);
    sessionC = new KeygenSession('c', partyIds, threshold, precomputedPaillierPrimesC);
  });

  test('round 1', async () => {
    const keygenRound1A = new KeygenRound1(sessionA, sessionA.inputForRound1);
    outputRound1A = await keygenRound1A.process();

    const keygenRound1B = new KeygenRound1(sessionB, sessionB.inputForRound1);
    outputRound1B = await keygenRound1B.process();

    const keygenRound1C = new KeygenRound1(sessionC, sessionC.inputForRound1);
    outputRound1C = await keygenRound1C.process();
  });

  test('round 2', async () => {
    const allBroadcasts = [
      ...outputRound1A.broadcasts,
      ...outputRound1B.broadcasts,
      ...outputRound1C.broadcasts,
    ].map((b) => b.toJSON()).map((b) => KeygenBroadcastForRound2.fromJSON(b));
    assert.equal(allBroadcasts.length, 3);

    const keygenRound2A = new KeygenRound2(sessionA, outputRound1A.inputForRound2);
    allBroadcasts.forEach((b) => keygenRound2A.handleBroadcastMessage(b));
    outputRound2A = keygenRound2A.process();

    const keygenRound2B = new KeygenRound2(sessionB, outputRound1B.inputForRound2);
    allBroadcasts.forEach((b) => keygenRound2B.handleBroadcastMessage(b));
    outputRound2B = keygenRound2B.process();

    const keygenRound2C = new KeygenRound2(sessionC, outputRound1C.inputForRound2);
    allBroadcasts.forEach((b) => keygenRound2C.handleBroadcastMessage(b));
    outputRound2C = keygenRound2C.process();
  });

  test('round 3', async () => {
    const allBroadcasts = [
      ...outputRound2A.broadcasts,
      ...outputRound2B.broadcasts,
      ...outputRound2C.broadcasts,
    ].map((b) => b.toJSON()).map((b) => KeygenBroadcastForRound3.fromJSON(b));
    assert.equal(allBroadcasts.length, 3);

    const keygenRound3A = new KeygenRound3(sessionA, outputRound2A.inputForRound3);
    allBroadcasts.forEach((b) => keygenRound3A.handleBroadcastMessage(b));
    outputRound3A = keygenRound3A.process();

    const keygenRound3B = new KeygenRound3(sessionB, outputRound2B.inputForRound3);
    allBroadcasts.forEach((b) => keygenRound3B.handleBroadcastMessage(b));
    outputRound3B = keygenRound3B.process();

    const keygenRound3C = new KeygenRound3(sessionC, outputRound2C.inputForRound3);
    allBroadcasts.forEach((b) => keygenRound3C.handleBroadcastMessage(b));
    outputRound3C = keygenRound3C.process();
  });

  test('round 4', async () => {
    const allBroadcasts = [
      ...outputRound3A.broadcasts,
      ...outputRound3B.broadcasts,
      ...outputRound3C.broadcasts,
    ].map((b) => b.toJSON()).map((b) => KeygenBroadcastForRound4.fromJSON(b));
    assert.equal(allBroadcasts.length, 3);
    const allMessages = [
      ...outputRound3A.directMessages,
      ...outputRound3B.directMessages,
      ...outputRound3C.directMessages,
    ].map((m) => m.toJSON()).map((m) => KeygenDirectMessageForRound4.fromJSON(m));
    assert.equal(allMessages.length, 6);

    const keygenRound4A = new KeygenRound4(sessionA, outputRound3A.inputForRound4);
    allBroadcasts.forEach((b) => keygenRound4A.handleBroadcastMessage(b));
    const messagesForA = allMessages.filter((m) => m.to === 'a');
    messagesForA.forEach((m) => keygenRound4A.handleDirectMessage(m));
    outputRound4A = keygenRound4A.process();

    const keygenRound4B = new KeygenRound4(sessionB, outputRound3B.inputForRound4);
    allBroadcasts.forEach((b) => keygenRound4B.handleBroadcastMessage(b));
    const messagesForB = allMessages.filter((m) => m.to === 'b');
    messagesForB.forEach((m) => keygenRound4B.handleDirectMessage(m));
    outputRound4B = keygenRound4B.process();

    const keygenRound4C = new KeygenRound4(sessionC, outputRound3C.inputForRound4);
    allBroadcasts.forEach((b) => keygenRound4C.handleBroadcastMessage(b));
    const messagesForC = allMessages.filter((m) => m.to === 'c');
    messagesForC.forEach((m) => keygenRound4C.handleDirectMessage(m));
    outputRound4C = keygenRound4C.process();
  });

  test('round 5', async () => {
    const allBroadcasts = [
      ...outputRound4A.broadcasts,
      ...outputRound4B.broadcasts,
      ...outputRound4C.broadcasts,
    ].map((b) => b.toJSON()).map((b) => KeygenBroadcastForRound5.fromJSON(b));
    assert.equal(allBroadcasts.length, 3);

    const keygenRound5A = new KeygenRound5(sessionA, outputRound4A.inputForRound5);
    allBroadcasts.forEach((b) => keygenRound5A.handleBroadcastMessage(b));
    outputRound5A = keygenRound5A.process();

    const keygenRound5B = new KeygenRound5(sessionB, outputRound4B.inputForRound5);
    allBroadcasts.forEach((b) => keygenRound5B.handleBroadcastMessage(b));
    outputRound5B = keygenRound5B.process();

    const keygenRound5C = new KeygenRound5(sessionC, outputRound4C.inputForRound5);
    allBroadcasts.forEach((b) => keygenRound5C.handleBroadcastMessage(b));
    outputRound5C = keygenRound5C.process();

    assert.deepEqual(
      Hasher.create().update(outputRound5A.UpdatedConfig).digestBigint(),
      Hasher.create().update(outputRound5B.UpdatedConfig).digestBigint(),
    );
    assert.deepEqual(
      Hasher.create().update(outputRound5A.UpdatedConfig).digestBigint(),
      Hasher.create().update(outputRound5C.UpdatedConfig).digestBigint(),
    );
  });

  test('public key eth address valid', async () => {
    const partyConfigA = outputRound5A.UpdatedConfig;
    const pubPoint = partyConfigA.publicPoint();
    const address = ethAddress(pubPoint);

    // As address is different each time, we can only check that it is valid
    // Which is sort of a no-test frankly
    assert(ethers.isAddress(address));

    // console.log('party a', JSON.stringify(serializePartySecretKeyConfig(outputRound5A.UpdatedConfig), null, 2));
    // console.log('party c', JSON.stringify(serializePartySecretKeyConfig(outputRound5B.UpdatedConfig), null, 2));
    // console.log('party b', JSON.stringify(serializePartySecretKeyConfig(outputRound5C.UpdatedConfig), null, 2));
  });
});
