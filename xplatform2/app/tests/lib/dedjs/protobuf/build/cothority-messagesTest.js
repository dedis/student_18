const ChaiAsPromised = require("chai-as-promised");
chai.use(ChaiAsPromised);
chai.should();

const ObjectType = require("../../../../../shared/lib/dedjs/ObjectType");
const Convert = require("../../../../../shared/lib/dedjs/Convert");
const Helper = require("../../../../../shared/lib/dedjs/Helper");

const CothorityMessages = require("../../../../../shared/lib/dedjs/network/cothority-messages");

const CONODE_ADDRESS = "tls://10.0.2.2:7002";
const CONODE_PUBLIC_KEY = "HkDzpR5Imd7WNx8kl2lJcIVRVn8gfDByJnmlfrYh/zU=";
const CONODE_PUBLIC_KEY_BYTE_ARRAY = Convert.base64ToByteArray(CONODE_PUBLIC_KEY);
const CONODE_DESCRIPTION = "Conode_1";
const CONODE_ID_REAL = "z6kCTQ77Xna9yfgKka5lNQ==";
const CONODE_ID_REAL_BYTE_ARRAY = Convert.base64ToByteArray(CONODE_ID_REAL);

const MODEL_ROSTER = { "fields": { "id": { "type": "bytes", "id": 1 }, "list": { "rule": "repeated", "type": "ServerIdentity", "id": 2 }, "aggregate": { "rule": "required", "type": "bytes", "id": 3 } } };

const PRIVATE_KEY = "AWKlOlcTuCHEV/fKX0X1IoAoBU0n1c5iKp/SWRLj3T4=";
const PRIVATE_KEY_BYTE_ARRAY = Convert.base64ToByteArray(PRIVATE_KEY);
const PUBLIC_KEY = "y4JMDWrle6RMV+0BKU92Xbu8+J8VkZ5kV3SvSr2ZxHw=";
const PUBLIC_KEY_BYTE_ARRAY = Convert.base64ToByteArray(PUBLIC_KEY);
const PUBLIC_COMPLETE_KEY = "BBmiuL/uxUuItsuFVQJT4oUv4qZrb1fYQ+GL/ZTpZ43MfMSZvUqvdFdknpEVn/i8u112TykB7VdMpHvlag1Mgss=";
const PUBLIC_COMPLETE_KEY_BYTE_ARRAY = Convert.base64ToByteArray(PUBLIC_COMPLETE_KEY);

const ROSTER_ID = "8yc0TaIweWRyMA==";
const ROSTER_ID_BYTE_ARRAY = Convert.base64ToByteArray(ROSTER_ID);
const ROSTER_LIST = [
  {
    "public": "HkDzpR5Imd7WNx8kl2lJcIVRVn8gfDByJnmlfrYh/zU=",
    "id": "z6kCTQ77Xna9yfgKka5lNQ==",
    "address": "tls://10.0.2.2:7002",
    "description": "Conode_1"
  },
  {
    "public": "Fx6zzvJM6VzxfByLY2+uArGPtd2lHKPVmoXGMhdaFCA=",
    "id": "Qd8XkrUlVEeClO9I95nklQ==",
    "address": "tls://10.0.2.2:7004",
    "description": "Conode_2"
  },
  {
    "public": "j53MMKZNdtLlglcK9Ct1YYtkbbEOfq3R8ZoJOFIu6tE=",
    "id": "tUq+0651WRaAI4aTQC0d8w==",
    "address": "tls://10.0.2.2:7006",
    "description": "Conode_3"
  }
];
const ROSTER_LIST_SERVER_IDENTITIES = ROSTER_LIST.map(conode => {
  conode.public = Convert.base64ToByteArray(conode.public);
  conode.id = Convert.base64ToByteArray(conode.id);

  return Convert.toServerIdentity(conode.address, conode.public, conode.description, conode.id);
});
const ROSTER_AGGREGATE = "q+G+7n6FXsY7hpxK3m119GuDHnchS6wqTE0sZE/fOKg=";
const ROSTER_AGGREGATE_BYTE_ARRAY = Convert.base64ToByteArray(ROSTER_AGGREGATE);

const POP_DESC_NAME = "Ced's Gang";
const POP_DESC_DATETIME = "Thu, 30 Nov 2017 11:12:00 GMT";
const POP_DESC_LOCATION = "INM, Lausanne";
const POP_DESC_ROSTER = CothorityMessages.createRoster(ROSTER_ID_BYTE_ARRAY, ROSTER_LIST_SERVER_IDENTITIES, ROSTER_AGGREGATE_BYTE_ARRAY);

const FINAL_POP_DESC = CothorityMessages.createPopDesc(POP_DESC_NAME, POP_DESC_DATETIME, POP_DESC_LOCATION, POP_DESC_ROSTER);
let FINAL_ATTENDEES = ["HkDzpR5Imd7WNx8kl2lJcIVRVn8gfDByJnmlfrYh/zU=", "Fx6zzvJM6VzxfByLY2+uArGPtd2lHKPVmoXGMhdaFCA=", "j53MMKZNdtLlglcK9Ct1YYtkbbEOfq3R8ZoJOFIu6tE="];
FINAL_ATTENDEES = FINAL_ATTENDEES.map(base64Key => {
  return Convert.base64ToByteArray(base64Key);
});
const FINAL_SIGNATURE = Convert.base64ToByteArray("q+G+7n6FXsY7hpxK3m119GuDHnchS6wqTE0sZE/fOKg=");
const FINAL_MERGED = false;
const FINAL_STATEMENT = CothorityMessages.createFinalStatement(FINAL_POP_DESC, FINAL_ATTENDEES, FINAL_SIGNATURE, FINAL_MERGED);

const STORE_CONFIG_ENCODED = Convert.base64ToByteArray("Ct4CCgpDZWQncyBHYW5nEh1UaHUsIDMwIE5vdiAyMDE3IDExOjEyOjAwIEdNVBoNSU5NLCBMYXVzYW5uZSKhAhJTCiAeQPOlHkiZ3tY3HySXaUlwhVFWfyB8MHImeaV+tiH/NRIQz6kCTQ77Xna9yfgKka5lNRoTdGNwOi8vMTAuMC4yLjI6NzAwMiIIQ29ub2RlXzESUwogFx6zzvJM6VzxfByLY2+uArGPtd2lHKPVmoXGMhdaFCASEEHfF5K1JVRHgpTvSPeZ5JUaE3RjcDovLzEwLjAuMi4yOjcwMDQiCENvbm9kZV8yElMKII+dzDCmTXbS5YJXCvQrdWGLZG2xDn6t0fGaCThSLurREhC1Sr7TrnVZFoAjhpNALR3zGhN0Y3A6Ly8xMC4wLjIuMjo3MDA2IghDb25vZGVfMxogq+G+7n6FXsY7hpxK3m119GuDHnchS6wqTE0sZE/fOKgSIKvhvu5+hV7GO4acSt5tdfRrgx53IUusKkxNLGRP3zio");

const POP_DESC_ID = Convert.base64ToByteArray("z6kCTQ77Xna9yfgKka5lNQ==");

const FINALIZE_REQUEST_ENCODED = Convert.base64ToByteArray("ChDPqQJNDvtedr3J+AqRrmU1EiAeQPOlHkiZ3tY3HySXaUlwhVFWfyB8MHImeaV+tiH/NRIgFx6zzvJM6VzxfByLY2+uArGPtd2lHKPVmoXGMhdaFCASII+dzDCmTXbS5YJXCvQrdWGLZG2xDn6t0fGaCThSLurRGiCr4b7ufoVexjuGnErebXX0a4MedyFLrCpMTSxkT984qA==");

const PIN = "123456";
const PIN_REQUEST_ENCODED = Convert.base64ToByteArray("CgYxMjM0NTYSIMuCTA1q5XukTFftASlPdl27vPifFZGeZFd0r0q9mcR8");

const FETCH_REQUEST_ENCODED = Convert.base64ToByteArray("ChDPqQJNDvtedr3J+AqRrmU1");

describe("CothorityMessages", function () {
  describe("#getModel", function () {
    it("should throw an error when name is not a string", function () {
      expect(() => CothorityMessages.getModel(42)).to.throw();
    });

    it("should throw an error when try to  get an unknown model", function () {
      expect(() => CothorityMessages.getModel("UNKNOWN_MODEL")).to.throw();
    });

    it("should correctly get a known model", function () {
      const model = CothorityMessages.getModel(ObjectType.ROSTER);

      JSON.parse(JSON.stringify(model)).should.deep.equal(MODEL_ROSTER);
    });
  });

  describe("#createKeyPair", function () {
    it("should throw an error when publicKey is not a byte array", function () {
      expect(() => CothorityMessages.createKeyPair("PUBLIC_KEY_BYTE_ARRAY", PRIVATE_KEY_BYTE_ARRAY, PUBLIC_COMPLETE_KEY_BYTE_ARRAY)).to.throw();
    });

    it("should throw an error when privateKey is not a byte array", function () {
      expect(() => CothorityMessages.createKeyPair(PUBLIC_KEY_BYTE_ARRAY, "PRIVATE_KEY_BYTE_ARRAY", PUBLIC_COMPLETE_KEY_BYTE_ARRAY)).to.throw();
    });

    it("should throw an error when publicCompleteKey is not a byte array", function () {
      expect(() => CothorityMessages.createKeyPair(PUBLIC_KEY_BYTE_ARRAY, PRIVATE_KEY_BYTE_ARRAY, "PUBLIC_COMPLETE_KEY_BYTE_ARRAY")).to.throw();
    });

    it("should create an object of type KeyPair", function () {
      const keyPair = CothorityMessages.createKeyPair(PUBLIC_KEY_BYTE_ARRAY, PRIVATE_KEY_BYTE_ARRAY, PUBLIC_COMPLETE_KEY_BYTE_ARRAY);

      Helper.isOfType(keyPair, ObjectType.KEY_PAIR).should.be.true;
    });

    it("should correctly create a key pair even without complete public key", function () {
      const keyPair = CothorityMessages.createKeyPair(PUBLIC_KEY_BYTE_ARRAY, PRIVATE_KEY_BYTE_ARRAY, undefined);

      keyPair.public.should.deep.equal(PUBLIC_KEY_BYTE_ARRAY);
      keyPair.private.should.deep.equal(PRIVATE_KEY_BYTE_ARRAY);
      keyPair.publicComplete.should.be.empty;
    });

    it("should correctly create a key pair", function () {
      const keyPair = CothorityMessages.createKeyPair(PUBLIC_KEY_BYTE_ARRAY, PRIVATE_KEY_BYTE_ARRAY, PUBLIC_COMPLETE_KEY_BYTE_ARRAY);

      keyPair.public.should.deep.equal(PUBLIC_KEY_BYTE_ARRAY);
      keyPair.private.should.deep.equal(PRIVATE_KEY_BYTE_ARRAY);
      keyPair.publicComplete.should.deep.equal(PUBLIC_COMPLETE_KEY_BYTE_ARRAY);
    });
  });

  describe("#createServerIdentity", function () {
    it("should throw an error when publicKey is not a byte array", function () {
      expect(() => CothorityMessages.createServerIdentity("CONODE_PUBLIC_KEY_BYTE_ARRAY", CONODE_ID_REAL_BYTE_ARRAY, CONODE_ADDRESS, CONODE_DESCRIPTION)).to.throw();
    });

    it("should throw an error when id is not a byte array", function () {
      expect(() => CothorityMessages.createServerIdentity(CONODE_PUBLIC_KEY_BYTE_ARRAY, "CONODE_ID_REAL_BYTE_ARRAY", CONODE_ADDRESS, CONODE_DESCRIPTION)).to.throw();
    });

    it("should throw an error when address is not a string", function () {
      expect(() => CothorityMessages.createServerIdentity(CONODE_PUBLIC_KEY_BYTE_ARRAY, CONODE_ID_REAL_BYTE_ARRAY, 42, CONODE_DESCRIPTION)).to.throw();
    });

    it("should throw an error when desc is not a string", function () {
      expect(() => CothorityMessages.createServerIdentity(CONODE_PUBLIC_KEY_BYTE_ARRAY, CONODE_ID_REAL_BYTE_ARRAY, CONODE_ADDRESS, 42)).to.throw();
    });

    it("should create an object of type ServerIdentity", function () {
      const serverIdentity = CothorityMessages.createServerIdentity(CONODE_PUBLIC_KEY_BYTE_ARRAY, CONODE_ID_REAL_BYTE_ARRAY, CONODE_ADDRESS, CONODE_DESCRIPTION);

      Helper.isOfType(serverIdentity, ObjectType.SERVER_IDENTITY).should.be.true;
    });

    it("should correctly create a server identity", function () {
      const serverIdentity = CothorityMessages.createServerIdentity(CONODE_PUBLIC_KEY_BYTE_ARRAY, CONODE_ID_REAL_BYTE_ARRAY, CONODE_ADDRESS, CONODE_DESCRIPTION);

      serverIdentity.public.should.deep.equal(CONODE_PUBLIC_KEY_BYTE_ARRAY);
      serverIdentity.id.should.deep.equal(CONODE_ID_REAL_BYTE_ARRAY);
      serverIdentity.address.should.equal(CONODE_ADDRESS);
      serverIdentity.description.should.equal(CONODE_DESCRIPTION);
    });
  });

  describe("#createRoster", function () {
    it("should throw an error when id is not a byte array", function () {
      expect(() => CothorityMessages.createRoster("ROSTER_ID_BYTE_ARRAY", ROSTER_LIST_SERVER_IDENTITIES, ROSTER_AGGREGATE_BYTE_ARRAY)).to.throw();
    });

    it("should throw an error when list is not an array", function () {
      expect(() => CothorityMessages.createRoster(ROSTER_ID_BYTE_ARRAY, {}, ROSTER_AGGREGATE_BYTE_ARRAY)).to.throw();
    });

    it("should throw an error when list is not an array of ServerIdentity", function () {
      expect(() => CothorityMessages.createRoster(ROSTER_ID_BYTE_ARRAY, [1, 2, 3], ROSTER_AGGREGATE_BYTE_ARRAY)).to.throw();
    });

    it("should throw an error when aggregate is not a byte array", function () {
      expect(() => CothorityMessages.createRoster(ROSTER_ID_BYTE_ARRAY, ROSTER_LIST_SERVER_IDENTITIES, "ROSTER_AGGREGATE_BYTE_ARRAY")).to.throw();
    });

    it("should create an object of type Roster", function () {
      const roster = CothorityMessages.createRoster(ROSTER_ID_BYTE_ARRAY, ROSTER_LIST_SERVER_IDENTITIES, ROSTER_AGGREGATE_BYTE_ARRAY);

      Helper.isOfType(roster, ObjectType.ROSTER).should.be.true;
    });

    it("should correctly create a roster even when it lacks an id", function () {
      const roster = CothorityMessages.createRoster(undefined, ROSTER_LIST_SERVER_IDENTITIES, ROSTER_AGGREGATE_BYTE_ARRAY);

      roster.id.should.be.empty;
      for (let i = 0; i < ROSTER_LIST_SERVER_IDENTITIES.length; ++i) {
        roster.list[i].public.should.deep.equal(ROSTER_LIST_SERVER_IDENTITIES[i].public);
        roster.list[i].id.should.deep.equal(ROSTER_LIST_SERVER_IDENTITIES[i].id);
        roster.list[i].address.should.equal(ROSTER_LIST_SERVER_IDENTITIES[i].address);
        roster.list[i].description.should.equal(ROSTER_LIST_SERVER_IDENTITIES[i].description);
      }
      roster.aggregate.should.deep.equal(ROSTER_AGGREGATE_BYTE_ARRAY);
    });

    it("should correctly create a roster", function () {
      const roster = CothorityMessages.createRoster(ROSTER_ID_BYTE_ARRAY, ROSTER_LIST_SERVER_IDENTITIES, ROSTER_AGGREGATE_BYTE_ARRAY);

      roster.id.should.deep.equal(ROSTER_ID_BYTE_ARRAY);
      for (let i = 0; i < ROSTER_LIST_SERVER_IDENTITIES.length; ++i) {
        roster.list[i].public.should.deep.equal(ROSTER_LIST_SERVER_IDENTITIES[i].public);
        roster.list[i].id.should.deep.equal(ROSTER_LIST_SERVER_IDENTITIES[i].id);
        roster.list[i].address.should.equal(ROSTER_LIST_SERVER_IDENTITIES[i].address);
        roster.list[i].description.should.equal(ROSTER_LIST_SERVER_IDENTITIES[i].description);
      }
      roster.aggregate.should.deep.equal(ROSTER_AGGREGATE_BYTE_ARRAY);
    });
  });

  describe("#createStatusRequest", function () {
    it("should be able to create a status request", function () {
      const statusRequest = CothorityMessages.createStatusRequest();

      statusRequest.should.be.empty;
    });
  });

  describe("#createPopDesc", function () {
    it("should throw an error when name is not a string", function () {
      expect(() => CothorityMessages.createPopDesc(42, POP_DESC_DATETIME, POP_DESC_LOCATION, POP_DESC_ROSTER)).to.throw();
    });

    it("should throw an error when datetime is not a string", function () {
      expect(() => CothorityMessages.createPopDesc(POP_DESC_NAME, 42, POP_DESC_LOCATION, POP_DESC_ROSTER)).to.throw();
    });

    it("should throw an error when location is not a string", function () {
      expect(() => CothorityMessages.createPopDesc(POP_DESC_NAME, POP_DESC_DATETIME, 42, POP_DESC_ROSTER)).to.throw();
    });

    it("should throw an error when roster is not a Roster object", function () {
      expect(() => CothorityMessages.createPopDesc(POP_DESC_NAME, POP_DESC_DATETIME, POP_DESC_LOCATION, "POP_DESC_ROSTER")).to.throw();
    });

    it("should create an object of type PopDesc", function () {
      const popDesc = CothorityMessages.createPopDesc(POP_DESC_NAME, POP_DESC_DATETIME, POP_DESC_LOCATION, POP_DESC_ROSTER);

      Helper.isOfType(popDesc, ObjectType.POP_DESC);
    });

    it("should correctly create a PopDesc", function () {
      const popDesc = CothorityMessages.createPopDesc(POP_DESC_NAME, POP_DESC_DATETIME, POP_DESC_LOCATION, POP_DESC_ROSTER);

      popDesc.name.should.equal(POP_DESC_NAME);
      popDesc.datetime.should.equal(POP_DESC_DATETIME);
      popDesc.location.should.equal(POP_DESC_LOCATION);

      const roster = popDesc.roster;
      roster.id.should.deep.equal(POP_DESC_ROSTER.id);
      for (let i = 0; i < POP_DESC_ROSTER.length; ++i) {
        roster.list[i].public.should.deep.equal(POP_DESC_ROSTER.list[i].public);
        roster.list[i].id.should.deep.equal(POP_DESC_ROSTER.list[i].id);
        roster.list[i].address.should.equal(POP_DESC_ROSTER.list[i].address);
        roster.list[i].description.should.equal(POP_DESC_ROSTER.list[i].description);
      }
      roster.aggregate.should.deep.equal(POP_DESC_ROSTER.aggregate);
    });
  });

  describe("#createPopToken", function () {
    it("should throw an error when final is not a FinalStatement", function () {
      expect(() => CothorityMessages.createPopToken("FINAL_STATEMENT", PRIVATE_KEY_BYTE_ARRAY, PUBLIC_KEY_BYTE_ARRAY)).to.throw();
    });

    it("should throw an error when privateKey is not a byte array", function () {
      expect(() => CothorityMessages.createPopToken(FINAL_STATEMENT, "PRIVATE_KEY_BYTE_ARRAY", PUBLIC_KEY_BYTE_ARRAY)).to.throw();
    });

    it("should throw an error when publicKey is not a byte array", function () {
      expect(() => CothorityMessages.createPopToken(FINAL_STATEMENT, PRIVATE_KEY_BYTE_ARRAY, "PUBLIC_KEY_BYTE_ARRAY")).to.throw();
    });

    it("should create an object of type PopToken", function () {
      const popToken = CothorityMessages.createPopToken(FINAL_STATEMENT, PRIVATE_KEY_BYTE_ARRAY, PUBLIC_KEY_BYTE_ARRAY);

      Helper.isOfType(popToken, ObjectType.POP_TOKEN);
    });

    it("should correctly create a PopToken", function () {
      const popToken = CothorityMessages.createPopToken(FINAL_STATEMENT, PRIVATE_KEY_BYTE_ARRAY, PUBLIC_KEY_BYTE_ARRAY);

      const final = popToken.final;
      const desc = final.desc;
      desc.name.should.equal(FINAL_STATEMENT.desc.name);
      desc.datetime.should.equal(FINAL_STATEMENT.desc.datetime);
      desc.location.should.equal(FINAL_STATEMENT.desc.location);

      const roster = desc.roster;
      roster.id.should.deep.equal(FINAL_STATEMENT.desc.roster.id);
      for (let i = 0; i < POP_DESC_ROSTER.length; ++i) {
        roster.list[i].public.should.deep.equal(FINAL_STATEMENT.desc.roster.list[i].public);
        roster.list[i].id.should.deep.equal(FINAL_STATEMENT.desc.roster.list[i].id);
        roster.list[i].address.should.equal(FINAL_STATEMENT.desc.roster.list[i].address);
        roster.list[i].description.should.equal(FINAL_STATEMENT.desc.roster.list[i].description);
      }
      roster.aggregate.should.deep.equal(FINAL_STATEMENT.desc.roster.aggregate);

      final.attendees.should.deep.equal(FINAL_STATEMENT.attendees);
      final.signature.should.deep.equal(FINAL_STATEMENT.signature);
      final.merged.should.deep.equal(FINAL_STATEMENT.merged);

      popToken.private.should.deep.equal(PRIVATE_KEY_BYTE_ARRAY);
      popToken.public.should.deep.equal(PUBLIC_KEY_BYTE_ARRAY);
    });
  });

  describe("#createStoreConfig", function () {
    it("should throw an error when desc is not a PopDesc", function () {
      expect(() => CothorityMessages.createStoreConfig("FINAL_POP_DESC", FINAL_SIGNATURE)).to.throw();
    });

    it("should throw an error when signature is not a byte array", function () {
      expect(() => CothorityMessages.createStoreConfig(FINAL_POP_DESC, "FINAL_SIGNATURE")).to.throw();
    });

    it("should correctly create a store config", function () {
      const storeConfig = CothorityMessages.createStoreConfig(FINAL_POP_DESC, FINAL_SIGNATURE);

      storeConfig.desc.should.equal(FINAL_POP_DESC);
      storeConfig.signature.should.equal(FINAL_SIGNATURE);
    });
  });

  describe("#createFinalStatement", function () {
    it("should throw an error when desc is not a PopDesc", function () {
      expect(() => CothorityMessages.createFinalStatement("FINAL_POP_DESC", FINAL_ATTENDEES, FINAL_SIGNATURE, FINAL_MERGED)).to.throw();
    });

    it("should throw an error when attendees is not an array", function () {
      expect(() => CothorityMessages.createFinalStatement(FINAL_POP_DESC, "FINAL_ATTENDEES", FINAL_SIGNATURE, FINAL_MERGED)).to.throw();
    });

    it("should throw an error when attendees is not an array of byte arrays", function () {
      expect(() => CothorityMessages.createFinalStatement(FINAL_POP_DESC, ["a", "b"], FINAL_SIGNATURE, FINAL_MERGED)).to.throw();
    });

    it("should throw an error when signature is not a byte array", function () {
      expect(() => CothorityMessages.createFinalStatement(FINAL_POP_DESC, FINAL_ATTENDEES, "FINAL_SIGNATURE", FINAL_MERGED)).to.throw();
    });

    it("should throw an error when merged is not a boolean", function () {
      expect(() => CothorityMessages.createFinalStatement(FINAL_POP_DESC, FINAL_ATTENDEES, FINAL_SIGNATURE, "FINAL_MERGED")).to.throw();
    });

    it("should correctly create a final statement", function () {
      const finalStatement = CothorityMessages.createFinalStatement(FINAL_POP_DESC, FINAL_ATTENDEES, FINAL_SIGNATURE, FINAL_MERGED);

      Helper.isOfType(finalStatement, ObjectType.FINAL_STATEMENT);
    });

    it("should correctly create a final statement", function () {
      const finalStatement = CothorityMessages.createFinalStatement(FINAL_POP_DESC, FINAL_ATTENDEES, FINAL_SIGNATURE, FINAL_MERGED);

      const popDesc = finalStatement.desc;
      popDesc.name.should.equal(FINAL_POP_DESC.name);
      popDesc.datetime.should.equal(FINAL_POP_DESC.datetime);
      popDesc.location.should.equal(FINAL_POP_DESC.location);

      const roster = popDesc.roster;
      roster.id.should.deep.equal(FINAL_POP_DESC.roster.id);
      for (let i = 0; i < FINAL_POP_DESC.roster.length; ++i) {
        roster.list[i].public.should.deep.equal(FINAL_POP_DESC.roster.list[i].public);
        roster.list[i].id.should.deep.equal(FINAL_POP_DESC.roster.list[i].id);
        roster.list[i].address.should.equal(FINAL_POP_DESC.roster.list[i].address);
        roster.list[i].description.should.equal(FINAL_POP_DESC.roster.list[i].description);
      }
      roster.aggregate.should.deep.equal(FINAL_POP_DESC.roster.aggregate);

      finalStatement.attendees.should.deep.equal(FINAL_ATTENDEES);
      finalStatement.signature.should.deep.equal(FINAL_SIGNATURE);
      finalStatement.merged.should.deep.equal(FINAL_MERGED);
    });
  });

  describe("#createFinalizeRequest", function () {
    it("should throw an error when descId is not a byte array", function () {
      expect(() => CothorityMessages.createFinalizeRequest("POP_DESC_ID", FINAL_ATTENDEES, FINAL_SIGNATURE)).to.throw();
    });

    it("should throw an error when attendees is not an array", function () {
      expect(() => CothorityMessages.createFinalizeRequest(POP_DESC_ID, "FINAL_ATTENDEES", FINAL_SIGNATURE)).to.throw();
    });

    it("should throw an error when attendees is not an array of byte arrays", function () {
      expect(() => CothorityMessages.createFinalizeRequest(POP_DESC_ID, ["a", "b"], FINAL_SIGNATURE)).to.throw();
    });

    it("should throw an error when signature is not a byte array", function () {
      expect(() => CothorityMessages.createFinalizeRequest(POP_DESC_ID, FINAL_ATTENDEES, "FINAL_SIGNATURE")).to.throw();
    });

    it("should correctly create a finalize request", function () {
      const finalizeRequest = CothorityMessages.createFinalizeRequest(POP_DESC_ID, FINAL_ATTENDEES, FINAL_SIGNATURE);

      finalizeRequest.descId.should.equal(POP_DESC_ID);
      finalizeRequest.attendees.should.equal(FINAL_ATTENDEES);
      finalizeRequest.signature.should.equal(FINAL_SIGNATURE);
    });
  });

  describe("#createPinRequest", function () {
    it("should throw an error when pin is not a string", function () {
      expect(() => CothorityMessages.createPinRequest(42, PUBLIC_KEY_BYTE_ARRAY)).to.throw();
    });

    it("should throw an error when publicKey is not a byte array", function () {
      expect(() => CothorityMessages.createPinRequest(PIN, "PUBLIC_KEY_BYTE_ARRAY")).to.throw();
    });

    it("should correctly create a pin request", function () {
      const pinRequest = CothorityMessages.createPinRequest(PIN, PUBLIC_KEY_BYTE_ARRAY);

      pinRequest.pin.should.equal(PIN);
      pinRequest.public.should.equal(PUBLIC_KEY_BYTE_ARRAY)
    });
  });

  describe("#createFetchRequest", function () {
    it("should throw an error when id is not a byte array", function () {
      expect(() => CothorityMessages.createFetchRequest("POP_DESC_ID")).to.throw();
    });

    it("should correctly create a pin request", function () {
      const fetchRequest = CothorityMessages.createFetchRequest(POP_DESC_ID);

      fetchRequest.id.should.equal(POP_DESC_ID);
    });
  });
});
