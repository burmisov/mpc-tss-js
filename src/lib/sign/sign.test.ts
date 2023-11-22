import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { secp256k1 } from '@noble/curves/secp256k1';

import { AffinePointSerialized, PartyPublicKeyConfigSerialized, PartySecretKeyConfigSerialized } from "../keyConfig.js";
import { PaillierPublicKeySerialized, PaillierSecretKeySerialized, paillierPublicKeyFromSerialized, paillierSecretKeyFromSerialized } from '../paillier.js';

const publicKeyConfigA: PartyPublicKeyConfigSerialized = {
  partyId: 'a',
  ecdsa: {
    xHex: 'ac7ef6fdd8a10d04210861c9e8758e2372350d0f640847d36b49459fc4f2e899',
    yHex: 'cd59ef730add03d7d74a94a9871b37c45a19f20952d285eac87e9fb4c17f2342',
  },
  elgamal: {
    xHex: '8bc49ea932768866a74c40c150b29bdfb35104df2a3de2ca355b85c11036f31b',
    yHex: '19d66f19b2cb489016c7fbd44ed64c2778cc9401d5e2644323ae161b273d01cd',
  },
  paillier: {
    nHex: 'd1aea9edc62552a0efd81032207bc8da5342c4c4680a0aa6fda414131807b573ed3ca99fe7c36636df2a04064c28b801564304faff8d31c3a0ac5263ab5b1a54b08013d35c8cd5a4abfef6124bd04a90ee1a79121d501d48466c6b8ba03a94ebc20aac038499414dc35cfd423360fcbebd0cc75dc386e175ee3147a7055b58ed752cfe7716b09e7c6808438a411b06fe33f96918767ed04d5112ba7a016eb206169a1051f30e9be5c3c7c1e3f946fc78f5c47519bcb8db206e943aff34097875dddbbc257e673bbe125f1fe63d46e7275fdb6218ed9ad0ac5cf597b729c79447b339cda50f8d245d690016d5cc18e866c91171da6d17fa68e96c1afbf6881739',
  },
  pedersen: {
    nHex: 'd1aea9edc62552a0efd81032207bc8da5342c4c4680a0aa6fda414131807b573ed3ca99fe7c36636df2a04064c28b801564304faff8d31c3a0ac5263ab5b1a54b08013d35c8cd5a4abfef6124bd04a90ee1a79121d501d48466c6b8ba03a94ebc20aac038499414dc35cfd423360fcbebd0cc75dc386e175ee3147a7055b58ed752cfe7716b09e7c6808438a411b06fe33f96918767ed04d5112ba7a016eb206169a1051f30e9be5c3c7c1e3f946fc78f5c47519bcb8db206e943aff34097875dddbbc257e673bbe125f1fe63d46e7275fdb6218ed9ad0ac5cf597b729c79447b339cda50f8d245d690016d5cc18e866c91171da6d17fa68e96c1afbf6881739',
    sHex: '9cfe41908f79c00731b085039e981ce8ba5de34152b68ab5517b233cfdec5566fc466085cfbade91128c865f5f9ccfdf56d3f062b46ec0df9b9bc91d609f92e1372e295c1ce3f92ecc76bace95d931b73b5e96785f702d12cc5f7d3189926a802eaaf33117acfe60ab18de674290f98ae539674853f56978ea2ea9b131cbab0fe724bef4748e24cb2e0b8d1d6837221c227e5cde6ef1590ac0faf385ea0e46ae68d625589f549a27cc41c255170debe7a69ed5052e3f9c7a0faec668a3e867b3044f8abd41293388115921cd86e4096e0d6e29a2e03ac47409d3edb8394f72fc2c36527821fea339c01ed4e2fcb4770961274b25a723d866373bb3f4ff32ccea',
    tHex: '8a22c4c21ed19547f5eea7daaf83336da134bca7531de9dd90bae7b62eba7da578bca99f16fa15496c39ff1dd43ced2919b66c9abdca2151b36d070d516b21281baf2bbf64275d4e471b017ed6ff5bf66a7c5e9501fe7207c0e1a906cf7f4e7b3dafcb7ad3d5217d53f839209c664b2061b1ac18275bf4ca1ece31c7450f66b90edb018774ccfd01e35c07af8fc7e9b60aeaca77b3c7ec0f375228b796ff0ff8710e1d6cdc2880d6ec9de15dd7b737fce9613b1fbeaf611fcfe59dfb870b0d8cc7a7dcfd3b81ae51e3c03a8c0966a0965e91d5588bb073ec50d80f0e61c212b8155870007d685e35dbc957aa9ec85d161425971647c44cde4ae00a3f0dc2ea69',
  },
};

const publicKeyConfigB: PartyPublicKeyConfigSerialized = {
  partyId: 'b',
  ecdsa: {
    xHex: 'e636c580298dfe697ca9ac96154e31338527d0c2b1d0df4628a6df30208410f3',
    yHex: 'c46d513c7347d2bb52d032b9b51c4e844b9ad426559370f1ec3e372f2c357c11',
  },
  elgamal: {
    xHex: 'cb939579692716b0f601d5cfe42ab6b99dd689107b742821734f05becf5759f3',
    yHex: '0f58c94ceb3fd60fd793cc34e780c6830596803e73215c2b565ab226b65a6f53',
  },
  paillier: {
    nHex: 'b1811346bca66a01b74ceafe73527bc3e61854fa8f16dd111ea48b890a11d05a31c5692a6351de8802f33eff2ad0a01523bfc5ad52bc6746c56b6da344d45e92e2b73a0c0b27793d5ad2f7054ec43c6905359320f578031a2eba4314cea2f4925157ee2b284d030fa0bd3bafb2e1c3f8279e1162fc943d9514b8da8ab9bbdc8a2fddd3b1e584a428914f0fb67f7d518a3170ee8e71891b59839f691ba47c3027470b731f5b72231a08b51e5e21a4e4c74466a224c61e729cd227564ed79fc2233a23677370a98ba495b87fb5d591d2e155307fd4c65ba833a4f9180fb2f890e936ba49f634c6c2fc2d7dba53737ddebf425c40c3cc8173cccc7719e00c61b10d',
  },
  pedersen: {
    nHex: 'b1811346bca66a01b74ceafe73527bc3e61854fa8f16dd111ea48b890a11d05a31c5692a6351de8802f33eff2ad0a01523bfc5ad52bc6746c56b6da344d45e92e2b73a0c0b27793d5ad2f7054ec43c6905359320f578031a2eba4314cea2f4925157ee2b284d030fa0bd3bafb2e1c3f8279e1162fc943d9514b8da8ab9bbdc8a2fddd3b1e584a428914f0fb67f7d518a3170ee8e71891b59839f691ba47c3027470b731f5b72231a08b51e5e21a4e4c74466a224c61e729cd227564ed79fc2233a23677370a98ba495b87fb5d591d2e155307fd4c65ba833a4f9180fb2f890e936ba49f634c6c2fc2d7dba53737ddebf425c40c3cc8173cccc7719e00c61b10d',
    sHex: '25d99c6789b970e21e0bdce62746b227cf5e98053f056e4b546ef658e68980c6fdc821ba5588afa92b3c3c147193b1edea3fb30e91609fa163f94c28f8dcd86698155d526945505032f13a66c11cbeacc38454cac54c88e15f2c5859a94522df0137508e6ca65999d9702394f7ff102589b3a7703304403a144e97a234741483a9390abca6b96136a5f45f5cf1393fae9015cd285192ecf006e2624243c2e6fd55b1922bff51b27e26ae2dbee157dff833a38ff3eaa21d49b10b4dfb98ad03193006fd1b18b43da492331e631b933da51cbcd12dedb5dbdaa2cda6bfc7f19b0219e7662fbf3279247d550c55a3b7955407b4bbf281a216a736e29c5a82f76b93',
    tHex: '711cdad21103b76d63346cb5a700455db65332ff54516ce7af71078d0ac56ed7dad9827942b329af2ba15a350a9f50327d38d3e93d437abc0f78678f03943b10e5e5bd79ab9a5382231dc3924eadca3509cfed8b8e048b853a5edc695e5e2d1f87cf59df1419aba57891ec0def8a33209cbc1ab2d46f53c58bc7e1289221e706813306849c70470317eec4699de37b365dacb0e757bf7a4b98f3d581429bc63d99a17f7bd31e4e51a66c392bacd78957796a3dedee019dc0f7288b2b6324c3facf72d2006a75c14efacb993e656d102d8754715403f69d2ccb9858c98795093feb7ea5439438676d5b13fc874216584b888d1c5d516a25c001676927c93c2909',
  },
};

const publicKeyConfigC: PartyPublicKeyConfigSerialized = {
  partyId: 'c',
  ecdsa: {
    xHex: 'f3d1d2e987fda9d61baabe34dff98293becf23ff941aee4c1c28f449fb52c15c',
    yHex: 'f340b26c1d5d44e96dd1793d7318c00b0b06b2b20c156d977bbb1f1135fd59d2',
  },
  elgamal: {
    xHex: 'c89ec38b3124ddb11c54b6d9ada6d30a26d1f15beacf7fc97fa868a9751ed5be',
    yHex: '9caf8e22309718689ad89c2379b9e033c679d2f176c5bafbafa17bd058acd667',
  },
  paillier: {
    nHex: 'bb30b2dca895f4d44a76d71d07f5b9851dcf894ed507161215633bd09aaed20b49f57444673fcdfd6378b2d00632c3db57476c952a2ae013a7cffc6e02f9d1e26c00d66b3378516bd660cfdaa7b8736ef9d96dfaa92b3d74eb0839ee0c7d52149e67af590a4b1525cc6e324d43bdc22027432b2f84c396c5e19f0986524e6c733328fc59180f7257aa80f83e9575a43399e020ea4e19e286709e0049b672563a12ecb6da39eb4a92b388856207852a09df3c29695904c1828ae8ab02402d0698c8bd7bb93a4bd4dd249fd9fa48da2863ad5d7925dfef652ec1566a8018f6545a580109f9d6bcfa95a5c6b94faf16d0313eba63c0c68b7cf9ddef571a9b9204e9',
  },
  pedersen: {
    nHex: 'bb30b2dca895f4d44a76d71d07f5b9851dcf894ed507161215633bd09aaed20b49f57444673fcdfd6378b2d00632c3db57476c952a2ae013a7cffc6e02f9d1e26c00d66b3378516bd660cfdaa7b8736ef9d96dfaa92b3d74eb0839ee0c7d52149e67af590a4b1525cc6e324d43bdc22027432b2f84c396c5e19f0986524e6c733328fc59180f7257aa80f83e9575a43399e020ea4e19e286709e0049b672563a12ecb6da39eb4a92b388856207852a09df3c29695904c1828ae8ab02402d0698c8bd7bb93a4bd4dd249fd9fa48da2863ad5d7925dfef652ec1566a8018f6545a580109f9d6bcfa95a5c6b94faf16d0313eba63c0c68b7cf9ddef571a9b9204e9',
    sHex: '74c985d2a4a8f2d83cfb0b286e9d73adfef9eccfe9fa0069d40a39992364312584f26a63675bddeca5ff8642030165305f6d1529f78c9aa14207e63208b19249182a247c9d56892f124467e9f11e66a348e565f062f8b4c51c9fb90d998332421a2be5a4a566076fc9cd0a61ae462d56c8a14d67dd4afd4c4604eb9677bdf7f9d2f7ee1437922b51ebe5e69c60b1c8c13c3edad0e89c28ed19e8e512665a29706b42b2d456cb80e92c522a911b650b53a71fd05b45291345b472bf5f8bc481930aa48e56e255edfb81240b33f98f404161a4309d1852681a45daace646faafe391de7c25a9d6cf4cd8a3c8e9c90e4968eed5e9c62351902a571e73c42c12d0a8',
    tHex: 'a6bf36e3bc7da5877cc1221454801c2ca9abb7d327bc7387a1164c1c754dbcbc559076309be877841ba56f42abd8b5f0bc9d206549ba53435414be21c53cafc497153b8f31a2045ff653c47825114d328f3f7d7d9d868e4eef5f7c4d27743697871a33751314183373419e00550dd348903b88b600b8eb477055a1e5129d9c2ee8c26660a8214b8453bbcdfa701885bce490dc04ea4a13c6f63368c311bf680a137aa4e34fe921cd189f7b92d97d8363415818e425342c73e66634b14b581d23795ad92c745a04bfe7e8ef661a24281e9622507cecc2521515dae8fb2fc7056a70603eb4db081fbe6621ccb557348b0f7de95d78632fe7a394b62a36ac08faf6',
  },
};

const secretKeyConfigA: PartySecretKeyConfigSerialized = {
  partyId: 'a',
  curve: 'secp256k1',
  threshold: 1,
  ecdsaHex: '3ad0152a797ce37556a8fd801f47ee312503a836c3e67ece5f76bf2b31383754',
  elgamalHex: 'ddeab71050047bcc21122331b970d1cb8736b672b1a2ae4c4bc32cd7dc22e3e5',
  paillier: {
    pHex: 'dfe9d014636ed4e0f0955d0394690ce78eb76ebbc3dac4eb7a14dabc183258d229ba1fadc7c16dc649f917b8a116575afe0acf2569c0ea01c47c7eda42ed2647952db3b8776568edcc0848294aa5b00df89009b28e5f29543c11fbdd12ffe3b3ccb0ab0008993c76eb31fd9b8841114e9c866308733f1c491cf5cbefe6e240f7',
    qHex: 'efbaca1ef12377a7df2af12c77eea0b68ca8cca257f1f2b68e2c053a0f56c4f01f4f9b98012d46fedc5737e29ffec2070de21e222ebc439d16986e3c94a91cc2d3f715583a1af67cb689048cc606a98096aa84ca61185a614e970bb8ff7c2ac34e7e84fb86f288d6975320acce41e180d17af96b0780b5b05c71171161028d4f',
  },
  ridHex: '', // TODO
  chainKeyHex: '', // TODO
  publicPartyData: {
    a: publicKeyConfigA,
    b: publicKeyConfigB,
    c: publicKeyConfigC,
  },
}

const secretKeyConfigB: PartySecretKeyConfigSerialized = {
  partyId: 'b',
  curve: 'secp256k1',
  threshold: 1,
  ecdsaHex: '6ea9e76209df7ce5f3558cae8360d61dc24cb7a961690165763015f36ec3adb1',
  elgamalHex: '1db9d480baf5bb36241bdc63c6287972f3ec87695bdcd3af4600eb1cef596469',
  paillier: {
    pHex: 'eba66341ce03f706c9251018ecaca99991f3fa0d20436c36acc3daadb9ff27ecdee0bc91426081714256d4770f8a9c30fe877c5ee76199b7d2f4b5146e64e55f297611868327accfe022cbe58c9cc4c3535757622f426329566628109f9d2b6f68e9570db2826914cf8fbd49ac7adf063e20543e465ff1a8a27a8251c1e9fb23',
    qHex: 'c0d53c2d693dd4164a71f8de569aee28bd52549c2352d2d505ea3be9b5d277a6d002a8152af219fd0e79eaa2158daf5886a9bc55781b0d78eaca224819d847f61882d84304b65f243f1be10456844e359562fbeeb25a81af5abaa3ebdbe561f0dd56162ecafacf6def08250248b3082928b9e2da69abc236f78372915418be0f',
  },
  ridHex: '', // TODO
  chainKeyHex: '', // TODO
  publicPartyData: {
    a: publicKeyConfigA,
    b: publicKeyConfigB,
    c: publicKeyConfigC,
  },
}

const secretKeyConfigC: PartySecretKeyConfigSerialized = {
  partyId: 'c',
  curve: 'secp256k1',
  threshold: 1,
  ecdsaHex: 'a283b9999a42165690021bdce779be0a5f95c71bfeeb83fc8ce96cbbac4f240e',
  elgamalHex: '7d029768455538cfeb41ac20891f68ff2222196d6e457941464b8005065425d6',
  paillier: {
    pHex: 'd6622f55599636fbec8111420819edaa025542f3121c2594d4927520ab6ac045733a8902d90ca3dfce307adc5a00dc542c46a69d3fb8fe6818e27cc0150871b5729b799401f09523955eb83c4c56bcd3894adc3583f2b2f40549c021f0b9e9ed09d0e0bc1079db06885080edb6ddcd77339f74a502e1fedaf1f5082726381dd7',
    qHex: 'df8723a5e503690b3783a7d27a9a8081a650c102690b79b3d96c372a2514cc023bef218127750c7da5eb2403c0e73d45b4ecfe63df5860bc33792c767136f65c663cf2064caf6b1f1efeacede59ac57dbe1f53b01e31a0cb6026da00fb1702fa312992722e58036fcbe5d4f639d60fe3f111cec7e8364ae3a8441f7f36ab1b3f',
  },
  ridHex: '', // TODO
  chainKeyHex: '', // TODO
  publicPartyData: {
    a: publicKeyConfigA,
    b: publicKeyConfigB,
    c: publicKeyConfigC,
  },
}

describe('signature', () => {
  const checkPaillierFixture = (
    publicSerialized: PaillierPublicKeySerialized,
    privateSerialized: PaillierSecretKeySerialized,
  ) => {
    const pub = paillierPublicKeyFromSerialized(publicSerialized);
    const secret = paillierSecretKeyFromSerialized(privateSerialized);
    assert.deepStrictEqual(
      pub, secret.publicKey, 'public key does not match secret key',
    );
  }

  const checkCurvePointFixture = (
    publicSerialized: AffinePointSerialized,
    privateHex: string,
  ) => {
    const xbig = BigInt('0x' + publicSerialized.xHex);
    const ybig = BigInt('0x' + publicSerialized.yHex);
    const point = secp256k1.ProjectivePoint.fromAffine({
      x: xbig,
      y: ybig,
    });
    point.assertValidity();
    const scalar = BigInt('0x' + privateHex);
    const mul = secp256k1.ProjectivePoint.BASE.multiply(scalar);
    assert.strictEqual(
      xbig, mul.x, 'public key does not match secret key',
    );
    assert.strictEqual(
      ybig, mul.y, 'public key does not match secret key',
    );
  }

  it('fixtures valid', () => {
    checkPaillierFixture(
      publicKeyConfigA.paillier, secretKeyConfigA.paillier,
    );
    checkPaillierFixture(
      publicKeyConfigB.paillier, secretKeyConfigB.paillier,
    );
    checkPaillierFixture(
      publicKeyConfigC.paillier, secretKeyConfigC.paillier,
    );

    checkCurvePointFixture(
      publicKeyConfigA.ecdsa, secretKeyConfigA.ecdsaHex,
    );
    checkCurvePointFixture(
      publicKeyConfigB.ecdsa, secretKeyConfigB.ecdsaHex,
    );
    checkCurvePointFixture(
      publicKeyConfigC.ecdsa, secretKeyConfigC.ecdsaHex,
    );

    checkCurvePointFixture(
      publicKeyConfigA.elgamal, secretKeyConfigA.elgamalHex,
    );
    checkCurvePointFixture(
      publicKeyConfigA.elgamal, secretKeyConfigA.elgamalHex,
    );
    checkCurvePointFixture(
      publicKeyConfigA.elgamal, secretKeyConfigA.elgamalHex,
    );

    // TODO: check pedersen?
  });
});
