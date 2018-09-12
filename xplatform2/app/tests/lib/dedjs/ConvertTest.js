const ChaiAsPromised = require("chai-as-promised");
chai.use(ChaiAsPromised);
chai.should();

const TomlParser = require("toml");
const Tomlify = require("tomlify-j0.4");
const Helper = require("../../../shared/lib/dedjs/Helper");
const ObjectType = require("../../../shared/lib/dedjs/ObjectType");
const CothorityMessages = require("../../../shared/lib/dedjs/network/cothority-messages");
const Convert = require("../../../shared/lib/dedjs/Convert");
const PopToken = require("../../../shared/lib/dedjs/object/pop/att/PopToken");

const BYTE_ARRAY = new Uint8Array([243, 39, 52, 77, 162, 48, 121, 100, 114, 48]);
const HEX_STRING = "f327344da23079647230";
const BASE64_STRING = "8yc0TaIweWRyMA==";

const BASE_OBJECT = {};
const SIMPLE_OBJECT = {
  a: "a",
  b: "b"
};
const COMPLEX_OBJECT = {
  a: {
    a: [1, 2, 3, 4],
    b: {
      c: 3
    }
  },
  b: {
    a: {
      c: 4
    },
    b: ["2", "b", "1", "a"]
  }
};

const CONODE_ADDRESS = "tls://10.0.2.2:7002";
const CONODE_PUBLIC_KEY = "HkDzpR5Imd7WNx8kl2lJcIVRVn8gfDByJnmlfrYh/zU=";
const CONODE_PUBLIC_KEY_BYTE_ARRAY = Convert.base64ToByteArray(CONODE_PUBLIC_KEY);
const CONODE_DESCRIPTION = "Conode_1";
const CONODE_ID_UNDEFINED = undefined;
const CONODE_ID_REAL = "z6kCTQ77Xna9yfgKka5lNQ==";
const CONODE_ID_REAL_BYTE_ARRAY = Convert.base64ToByteArray(CONODE_ID_REAL);

const WEBSOCKET_ADDRESS = "ws://10.0.2.2:7003";
const REQUEST_PATH = "/path/to/dedis"
const WEBSOCKET_ADDRESS_FULL = WEBSOCKET_ADDRESS + REQUEST_PATH;

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
const ROSTER_LIST_BYTE_ARRAY = ROSTER_LIST.map(conode => {
  const copy = Helper.deepCopy(conode);
  copy.public = Convert.base64ToByteArray(conode.public);
  copy.id = Convert.base64ToByteArray(conode.id);

  return copy;
});
const ROSTER_AGGREGATE = "q+G+7n6FXsY7hpxK3m119GuDHnchS6wqTE0sZE/fOKg=";
const ROSTER_AGGREGATE_BYTE_ARRAY = Convert.base64ToByteArray(ROSTER_AGGREGATE);

const JSON_ROSTER_FULL = JSON.stringify({
  "id": ROSTER_ID,
  "list": ROSTER_LIST,
  "aggregate": ROSTER_AGGREGATE
});
const JSON_ROSTER_NO_ROSTERID = JSON.stringify({
  "list": ROSTER_LIST,
  "aggregate": ROSTER_AGGREGATE
});
const JSON_ROSTER_NO_CONODEID = JSON.stringify({
  "id": ROSTER_ID,
  "list": [
    {
      "public": "HkDzpR5Imd7WNx8kl2lJcIVRVn8gfDByJnmlfrYh/zU=",
      "address": "tls://10.0.2.2:7002",
      "description": "Conode_1"
    },
    {
      "public": "Fx6zzvJM6VzxfByLY2+uArGPtd2lHKPVmoXGMhdaFCA=",
      "address": "tls://10.0.2.2:7004",
      "description": "Conode_2"
    },
    {
      "public": "j53MMKZNdtLlglcK9Ct1YYtkbbEOfq3R8ZoJOFIu6tE=",
      "address": "tls://10.0.2.2:7006",
      "description": "Conode_3"
    }
  ],
  "aggregate": ROSTER_AGGREGATE
});
const JSON_ROSTER_NO_AGGREGATE = JSON.stringify({
  "id": ROSTER_ID,
  "list": ROSTER_LIST
});
const JSON_ROSTER_NO_LIST = JSON.stringify({
  "id": ROSTER_ID,
  "aggregate": ROSTER_AGGREGATE
});
const JSON_ROSTER_LIST_WRONG_TYPE = JSON.stringify({
  "id": ROSTER_ID,
  "list": BYTE_ARRAY,
  "aggregate": ROSTER_AGGREGATE
});

const TOML_ROSTER =
  "[[servers]]\n" +
  "  Address = \"tls://10.0.2.2:7002\"\n" +
  "  Public = \"HkDzpR5Imd7WNx8kl2lJcIVRVn8gfDByJnmlfrYh/zU=\"\n" +
  "  Description = \"Conode_1\"\n" +
  "[[servers]]\n" +
  "  Address = \"tls://10.0.2.2:7004\"\n" +
  "  Public = \"Fx6zzvJM6VzxfByLY2+uArGPtd2lHKPVmoXGMhdaFCA=\"\n" +
  "  Description = \"Conode_2\"\n" +
  "[[servers]]\n" +
  "  Address = \"tls://10.0.2.2:7006\"\n" +
  "  Public = \"j53MMKZNdtLlglcK9Ct1YYtkbbEOfq3R8ZoJOFIu6tE=\"\n" +
  "  Description = \"Conode_3\"";
const TOML_ROSTER_NO_SERVERS_LIST =
  "[[server]]\n" +
  "  Address = \"tls://10.0.2.2:7002\"\n" +
  "  Public = \"HkDzpR5Imd7WNx8kl2lJcIVRVn8gfDByJnmlfrYh/zU=\"\n" +
  "  Description = \"Conode_1\"\n" +
  "[[server]]\n" +
  "  Address = \"tls://10.0.2.2:7004\"\n" +
  "  Public = \"Fx6zzvJM6VzxfByLY2+uArGPtd2lHKPVmoXGMhdaFCA=\"\n" +
  "  Description = \"Conode_2\"\n" +
  "[[server]]\n" +
  "  Address = \"tls://10.0.2.2:7006\"\n" +
  "  Public = \"j53MMKZNdtLlglcK9Ct1YYtkbbEOfq3R8ZoJOFIu6tE=\"\n" +
  "  Description = \"Conode_3\"";

const PRIVATE_KEY = "AWKlOlcTuCHEV/fKX0X1IoAoBU0n1c5iKp/SWRLj3T4=";
const PRIVATE_KEY_BYTE_ARRAY = Convert.base64ToByteArray(PRIVATE_KEY);
const PUBLIC_KEY = "y4JMDWrle6RMV+0BKU92Xbu8+J8VkZ5kV3SvSr2ZxHw=";
const PUBLIC_KEY_BYTE_ARRAY = Convert.base64ToByteArray(PUBLIC_KEY);
const PUBLIC_COMPLETE_KEY = "BBmiuL/uxUuItsuFVQJT4oUv4qZrb1fYQ+GL/ZTpZ43MfMSZvUqvdFdknpEVn/i8u112TykB7VdMpHvlag1Mgss=";
const PUBLIC_COMPLETE_KEY_BYTE_ARRAY = Convert.base64ToByteArray(PUBLIC_COMPLETE_KEY);
const JSON_KEY_PAIR = JSON.stringify({
  "private": PRIVATE_KEY,
  "public": PUBLIC_KEY,
  "publicComplete": PUBLIC_COMPLETE_KEY
});
const JSON_KEY_PAIR_NO_COMPLETE = JSON.stringify({
  "private": PRIVATE_KEY,
  "public": PUBLIC_KEY
});

const ROSTER_LIST_SERVER_IDENTITIES = ROSTER_LIST.map(conode => {
  conode.public = Convert.base64ToByteArray(conode.public);
  conode.id = Convert.base64ToByteArray(conode.id);

  return Convert.toServerIdentity(conode.address, conode.public, conode.description, conode.id);
});
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

const POP_TOKEN = new PopToken(FINAL_STATEMENT, PRIVATE_KEY_BYTE_ARRAY, PUBLIC_KEY_BYTE_ARRAY);

const POP_DESC_HASH_JSON = Convert.objectToJson({
  hash: PRIVATE_KEY
});

const SERVER_IDENTITY_JSON = Convert.objectToJson({
  address: CONODE_ADDRESS,
  public: CONODE_PUBLIC_KEY,
  description: CONODE_DESCRIPTION,
  id: CONODE_ID_REAL
});

const ARRAY_OF_KEYS_JSON = Convert.objectToJson({
  array: [PUBLIC_KEY, PUBLIC_KEY, PUBLIC_KEY]
});

describe("Convert", function () {
  describe("#byteArrayToHex", function () {
    it("should throw an error when the input is not a byte array", function () {
      expect(() => Convert.byteArrayToHex("BYTE_ARRAY")).to.throw();
    });

    it("should correctly convert a byte array into its hexadecimal representation", function () {
      const actualHexString = Convert.byteArrayToHex(BYTE_ARRAY);

      actualHexString.should.equal(HEX_STRING);
    });
  });

  describe("#hexToByteArray", function () {
    it("should throw an error when the input is not a string", function () {
      expect(() => Convert.hexToByteArray(BYTE_ARRAY)).to.throw();
    });

    it("should correctly convert a hexadecimal string into its byte array representation", function () {
      const actualByteArray = Convert.hexToByteArray(HEX_STRING);

      actualByteArray.should.deep.equal(BYTE_ARRAY);
    });
  });

  describe("#byteArrayToBase64", function () {
    it("should throw an error when the input is not a byte array", function () {
      expect(() => Convert.byteArrayToBase64("BYTE_ARRAY")).to.throw();
    });

    it("should correctly convert a byte array into its base64 representation", function () {
      const actualBase64String = Convert.byteArrayToBase64(BYTE_ARRAY);

      actualBase64String.should.equal(BASE64_STRING);
    });
  });

  describe("#base64ToByteArray", function () {
    it("should throw an error when the input is not a string", function () {
      expect(() => Convert.base64ToByteArray(BYTE_ARRAY)).to.throw();
    });

    it("should correctly convert a base64 string into its byte array representation", function () {
      const actualByteArray = Convert.base64ToByteArray(BASE64_STRING);

      actualByteArray.should.deep.equal(BYTE_ARRAY);
    });
  });

  describe("#hexToBase64", function () {
    it("should throw an error when the input is not a string", function () {
      expect(() => Convert.hexToBase64(BYTE_ARRAY)).to.throw();
    });

    it("should correctly convert a hex string into its base64 representation", function () {
      const actualBase64String = Convert.hexToBase64(HEX_STRING);

      actualBase64String.should.equal(BASE64_STRING);
    });
  });

  describe("#base64ToHex", function () {
    it("should throw an error when the input is not a string", function () {
      expect(() => Convert.base64ToHex(BYTE_ARRAY)).to.throw();
    });

    it("should correctly convert a base64 string into its hex representation", function () {
      const actualHexString = Convert.base64ToHex(BASE64_STRING);

      actualHexString.should.equal(HEX_STRING);
    });
  });

  describe("#objectToJson", function () {
    it("should throw an error when the input is undefined", function () {
      expect(() => Convert.objectToJson(undefined)).to.throw();
    });

    it("should throw an error when the input is not an object", function () {
      expect(() => Convert.objectToJson(BYTE_ARRAY)).to.throw();
    });

    it("should correctly convert an object into its JSON representation", function () {
      // Base object.
      let actualJsonString = Convert.objectToJson(BASE_OBJECT);
      JSON.parse(actualJsonString).should.deep.equal(BASE_OBJECT);

      // Simple object.
      actualJsonString = Convert.objectToJson(SIMPLE_OBJECT);
      JSON.parse(actualJsonString).should.deep.equal(SIMPLE_OBJECT);

      // Complex object.
      actualJsonString = Convert.objectToJson(COMPLEX_OBJECT);
      JSON.parse(actualJsonString).should.deep.equal(COMPLEX_OBJECT);
    });
  });

  describe("#jsonToObject", function () {
    it("should throw an error when the input is not a string", function () {
      expect(() => Convert.jsonToObject(BYTE_ARRAY)).to.throw();
    });

    it("should correctly convert a JSON string into its object representation", function () {
      // Base object.
      let actualObject = Convert.jsonToObject(JSON.stringify(BASE_OBJECT));
      actualObject.should.deep.equal(BASE_OBJECT);

      // Simple object.
      actualObject = Convert.jsonToObject(JSON.stringify(SIMPLE_OBJECT));
      actualObject.should.deep.equal(SIMPLE_OBJECT);

      // Complex object.
      actualObject = Convert.jsonToObject(JSON.stringify(COMPLEX_OBJECT));
      actualObject.should.deep.equal(COMPLEX_OBJECT);
    });
  });

  describe("#objectToToml", function () {
    it("should throw an error when the input is undefined", function () {
      expect(() => Convert.objectToToml(undefined)).to.throw();
    });

    it("should throw an error when the input is not an object", function () {
      expect(() => Convert.objectToToml(BYTE_ARRAY)).to.throw();
    });

    it("should correctly convert an object into its TOML representation", function () {
      // Base object.
      let actualTomlString = Convert.objectToToml(BASE_OBJECT);
      TomlParser.parse(actualTomlString).should.deep.equal(BASE_OBJECT);

      // Simple object.
      actualTomlString = Convert.objectToToml(SIMPLE_OBJECT);
      TomlParser.parse(actualTomlString).should.deep.equal(SIMPLE_OBJECT);

      // Complex object.
      actualTomlString = Convert.objectToToml(COMPLEX_OBJECT);
      TomlParser.parse(actualTomlString).should.deep.equal(COMPLEX_OBJECT);
    });
  });

  describe("#tomlToObject", function () {
    it("should throw an error when the input is not a string", function () {
      expect(() => Convert.tomlToObject(BYTE_ARRAY)).to.throw();
    });

    it("should correctly convert an object into its TOML representation", function () {
      // Base object.
      let actualObject = Convert.tomlToObject(Tomlify.toToml(BASE_OBJECT));
      actualObject.should.deep.equal(BASE_OBJECT);

      // Simple object.
      actualObject = Convert.tomlToObject(Tomlify.toToml(SIMPLE_OBJECT));
      actualObject.should.deep.equal(SIMPLE_OBJECT);

      // Complex object.
      actualObject = Convert.tomlToObject(Tomlify.toToml(COMPLEX_OBJECT));
      actualObject.should.deep.equal(COMPLEX_OBJECT);
    });
  });

  describe("#jsonToToml", function () {
    it("should throw an error when the input is not a string", function () {
      expect(() => Convert.jsonToToml(BYTE_ARRAY)).to.throw();
    });

    it("should correctly convert a JSON string into its TOML representation", function () {
      // Base object.
      let actualObject = TomlParser.parse(Convert.jsonToToml(JSON.stringify(BASE_OBJECT)));
      actualObject.should.deep.equal(BASE_OBJECT);

      // Simple object.
      actualObject = TomlParser.parse(Convert.jsonToToml(JSON.stringify(SIMPLE_OBJECT)));
      actualObject.should.deep.equal(SIMPLE_OBJECT);

      // Complex object.
      actualObject = TomlParser.parse(Convert.jsonToToml(JSON.stringify(COMPLEX_OBJECT)));
      actualObject.should.deep.equal(COMPLEX_OBJECT);
    });
  });

  describe("#tomlToJson", function () {
    it("should throw an error when the input is not a string", function () {
      expect(() => Convert.tomlToJson(BYTE_ARRAY)).to.throw();
    });

    it("should correctly convert a TOML string into its JSON representation", function () {
      // Base object.
      let actualObject = JSON.parse(Convert.tomlToJson(Tomlify.toToml(BASE_OBJECT)));
      actualObject.should.deep.equal(BASE_OBJECT);

      // Simple object.
      actualObject = JSON.parse(Convert.tomlToJson(Tomlify.toToml(SIMPLE_OBJECT)));
      actualObject.should.deep.equal(SIMPLE_OBJECT);

      // Complex object.
      actualObject = JSON.parse(Convert.tomlToJson(Tomlify.toToml(COMPLEX_OBJECT)));
      actualObject.should.deep.equal(COMPLEX_OBJECT);
    });
  });

  describe("#tlsToWebsocket", function () {
    const conode = Convert.toServerIdentity(CONODE_ADDRESS, Convert.base64ToByteArray(CONODE_PUBLIC_KEY), CONODE_DESCRIPTION, CONODE_ID_UNDEFINED);

    it("should throw an error when the conode does not have the correct type", function () {
      expect(() => Convert.tlsToWebsocket(BYTE_ARRAY , REQUEST_PATH)).to.throw();
    });

    it("should throw an error when the path does not have the correct type", function () {
      expect(() => Convert.tlsToWebsocket(conode, BYTE_ARRAY)).to.throw();
    });

    it("should correctly convert a tls address from server identity into a WS address", function () {
      const websocketAddress = Convert.tlsToWebsocket(conode, REQUEST_PATH);

      websocketAddress.should.equal(WEBSOCKET_ADDRESS_FULL);
    });

    it("should correctly convert a tls address from a string into a WS address", function () {
      const websocketAddress = Convert.tlsToWebsocket(conode.address, REQUEST_PATH);

      websocketAddress.should.equal(WEBSOCKET_ADDRESS_FULL);
    });

  });

  describe("#parseJsonRoster", function () {
    it("should throw an error when the input is not a string", function () {
      expect(() => Convert.parseJsonRoster(BYTE_ARRAY)).to.throw();
    });

    it("should throw an error when the field list is undefined", function () {
      expect(() => Convert.parseJsonRoster(JSON_ROSTER_NO_LIST)).to.throw();
    });

    it("should throw an error when the field list is not an array", function () {
      expect(() => Convert.parseJsonRoster(JSON_ROSTER_LIST_WRONG_TYPE)).to.throw();
    });

    it("should return a Roster object", function () {
      const roster = Convert.parseJsonRoster(JSON_ROSTER_FULL);

      roster.constructor.name.should.equal(ObjectType.ROSTER);
    });

    it("should correctly parse the JSON roster when it is complete", function () {
      const roster = Convert.parseJsonRoster(JSON_ROSTER_FULL);

      roster.id.should.deep.equal(ROSTER_ID_BYTE_ARRAY);
      roster.list.length.should.equal(ROSTER_LIST.length);
      for (let i = 0; i < ROSTER_LIST.length; ++i) {
        roster.list[i].public.should.deep.equal(ROSTER_LIST_BYTE_ARRAY[i].public);
        roster.list[i].id.should.deep.equal(ROSTER_LIST_BYTE_ARRAY[i].id);
        roster.list[i].address.should.equal(ROSTER_LIST_BYTE_ARRAY[i].address);
        roster.list[i].description.should.equal(ROSTER_LIST_BYTE_ARRAY[i].description);
      }
      roster.aggregate.should.deep.equal(ROSTER_AGGREGATE_BYTE_ARRAY);
    });

    it("should correctly parse the JSON roster when it lacks the roster id", function () {
      const roster = Convert.parseJsonRoster(JSON_ROSTER_NO_ROSTERID);

      roster.id.should.be.empty;
      roster.list.length.should.equal(ROSTER_LIST.length);
      for (let i = 0; i < ROSTER_LIST.length; ++i) {
        roster.list[i].public.should.deep.equal(ROSTER_LIST_BYTE_ARRAY[i].public);
        roster.list[i].id.should.deep.equal(ROSTER_LIST_BYTE_ARRAY[i].id);
        roster.list[i].address.should.equal(ROSTER_LIST_BYTE_ARRAY[i].address);
        roster.list[i].description.should.equal(ROSTER_LIST_BYTE_ARRAY[i].description);
      }
      roster.aggregate.should.deep.equal(ROSTER_AGGREGATE_BYTE_ARRAY);
    });

    it("should correctly parse the JSON roster when the conodes do not have an id", function () {
      const roster = Convert.parseJsonRoster(JSON_ROSTER_NO_CONODEID);

      roster.id.should.deep.equal(ROSTER_ID_BYTE_ARRAY);
      roster.list.length.should.equal(ROSTER_LIST.length);
      for (let i = 0; i < ROSTER_LIST.length; ++i) {
        roster.list[i].public.should.deep.equal(ROSTER_LIST_BYTE_ARRAY[i].public);
        roster.list[i].id.should.deep.equal(ROSTER_LIST_BYTE_ARRAY[i].id);
        roster.list[i].address.should.equal(ROSTER_LIST_BYTE_ARRAY[i].address);
        roster.list[i].description.should.equal(ROSTER_LIST_BYTE_ARRAY[i].description);
      }
      roster.aggregate.should.deep.equal(ROSTER_AGGREGATE_BYTE_ARRAY);
    });

    it("should correctly parse the JSON roster when it lacks the aggregate", function () {
      const roster = Convert.parseJsonRoster(JSON_ROSTER_NO_AGGREGATE);

      roster.id.should.deep.equal(ROSTER_ID_BYTE_ARRAY);
      roster.list.length.should.equal(ROSTER_LIST.length);
      for (let i = 0; i < ROSTER_LIST.length; ++i) {
        roster.list[i].public.should.deep.equal(ROSTER_LIST_BYTE_ARRAY[i].public);
        roster.list[i].id.should.deep.equal(ROSTER_LIST_BYTE_ARRAY[i].id);
        roster.list[i].address.should.equal(ROSTER_LIST_BYTE_ARRAY[i].address);
        roster.list[i].description.should.equal(ROSTER_LIST_BYTE_ARRAY[i].description);
      }
      roster.aggregate.should.deep.equal(ROSTER_AGGREGATE_BYTE_ARRAY);
    });
  });

  describe("#parseTomlRoster", function () {
    it("should throw an error when the input is not a string", function () {
      expect(() => Convert.parseTomlRoster(BYTE_ARRAY)).to.throw();
    });

    it("should throw an error when the TOML does not have a servers list", function () {
      expect(() => Convert.parseTomlRoster(TOML_ROSTER_NO_SERVERS_LIST)).to.throw();
    });

    it("should return a Roster object", function () {
      const roster = Convert.parseTomlRoster(TOML_ROSTER);

      roster.constructor.name.should.equal(ObjectType.ROSTER);
    });

    it("should correctly parse the simple TOML roster", function () {
      const roster = Convert.parseTomlRoster(TOML_ROSTER);

      roster.id.should.be.empty;
      roster.list.length.should.equal(ROSTER_LIST.length);
      for (let i = 0; i < ROSTER_LIST.length; ++i) {
        roster.list[i].public.should.deep.equal(ROSTER_LIST_BYTE_ARRAY[i].public);
        roster.list[i].id.should.deep.equal(ROSTER_LIST_BYTE_ARRAY[i].id);
        roster.list[i].address.should.equal(ROSTER_LIST_BYTE_ARRAY[i].address);
        roster.list[i].description.should.equal(ROSTER_LIST_BYTE_ARRAY[i].description);
      }
      roster.aggregate.should.deep.equal(ROSTER_AGGREGATE_BYTE_ARRAY);
    });
  });

  describe("#parseJsonKeyPair", function () {
    it("should throw an error when the input is not a string", function () {
      expect(() => Convert.parseJsonKeyPair(BYTE_ARRAY)).to.throw();
    });

    it("should return a KeyPair object", function () {
      const keyPair = Convert.parseJsonKeyPair(JSON_KEY_PAIR);

      keyPair.constructor.name.should.equal(ObjectType.KEY_PAIR);
    });

    it("should correctly parse a key pair that does not contain a complete public key", function () {
      const keyPair = Convert.parseJsonKeyPair(JSON_KEY_PAIR_NO_COMPLETE);

      keyPair.private.should.deep.equal(PRIVATE_KEY_BYTE_ARRAY);
      keyPair.public.should.deep.equal(PUBLIC_KEY_BYTE_ARRAY);
      keyPair.publicComplete.should.be.empty;
    });

    it("should correctly parse a key pair that does contain a complete public key", function () {
      const keyPair = Convert.parseJsonKeyPair(JSON_KEY_PAIR);

      keyPair.private.should.deep.equal(PRIVATE_KEY_BYTE_ARRAY);
      keyPair.public.should.deep.equal(PUBLIC_KEY_BYTE_ARRAY);
      keyPair.publicComplete.should.deep.equal(PUBLIC_COMPLETE_KEY_BYTE_ARRAY);
    });
  });

  describe("#toServerIdentity", function () {
    it("should throw an error when address is not a string", function () {
      expect(() => {
        return Convert.toServerIdentity(BYTE_ARRAY, CONODE_PUBLIC_KEY_BYTE_ARRAY, CONODE_DESCRIPTION, CONODE_ID_REAL_BYTE_ARRAY);
      }).to.throw();
    });

    it("should throw an error when publicKey is not a byte array", function () {
      expect(() => {
        return Convert.toServerIdentity(CONODE_ADDRESS, "CONODE_PUBLIC_KEY_BYTE_ARRAY", CONODE_DESCRIPTION, CONODE_ID_REAL_BYTE_ARRAY);
      }).to.throw();
    });

    it("should throw an error when description is not a string", function () {
      expect(() => {
        return Convert.toServerIdentity(CONODE_ADDRESS, CONODE_PUBLIC_KEY_BYTE_ARRAY, BYTE_ARRAY, CONODE_ID_REAL_BYTE_ARRAY);
      }).to.throw();
    });

    it("should throw an error when id is not a byte array", function () {
      expect(() => {
        return Convert.toServerIdentity(CONODE_ADDRESS, CONODE_PUBLIC_KEY_BYTE_ARRAY, CONODE_DESCRIPTION, "CONODE_ID_REAL_BYTE_ARRAY");
      }).to.throw();
    });

    it("should throw an error when the address format is not correct", function () {
      expect(() => {
        return Convert.toServerIdentity("tls://10.0.2.2-7002", CONODE_PUBLIC_KEY_BYTE_ARRAY, CONODE_DESCRIPTION, CONODE_ID_REAL_BYTE_ARRAY);
      }).to.throw();
      expect(() => {
        return Convert.toServerIdentity("ws://10.0.2.2:7002", CONODE_PUBLIC_KEY_BYTE_ARRAY, CONODE_DESCRIPTION, CONODE_ID_REAL_BYTE_ARRAY);
      }).to.throw();
      expect(() => {
        return Convert.toServerIdentity("tls:/10.0.2.2:7002", CONODE_PUBLIC_KEY_BYTE_ARRAY, CONODE_DESCRIPTION, CONODE_ID_REAL_BYTE_ARRAY);
      }).to.throw();
      expect(() => {
        return Convert.toServerIdentity("tls://10.0.2.2:-1", CONODE_PUBLIC_KEY_BYTE_ARRAY, CONODE_DESCRIPTION, CONODE_ID_REAL_BYTE_ARRAY);
      }).to.throw();
      expect(() => {
        return Convert.toServerIdentity("tls://10.0.2.2:65535", CONODE_PUBLIC_KEY_BYTE_ARRAY, CONODE_DESCRIPTION, CONODE_ID_REAL_BYTE_ARRAY);
      }).to.throw();
    });

    it("should throw an error when the public key format is not correct", function () {
      expect(() => {
        return Convert.toServerIdentity(CONODE_ADDRESS, new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]), CONODE_DESCRIPTION, CONODE_ID_REAL_BYTE_ARRAY);
      }).to.throw();
    });

    it("should return a ServerIdentity object", function () {
      const serverIdentity = Convert.toServerIdentity(CONODE_ADDRESS, CONODE_PUBLIC_KEY_BYTE_ARRAY, CONODE_DESCRIPTION, CONODE_ID_REAL_BYTE_ARRAY);

      serverIdentity.constructor.name.should.equal(ObjectType.SERVER_IDENTITY);
    });

    it("should correctly create a ServerIdentity even if the id is undefined", function () {
      const serverIdentity = Convert.toServerIdentity(CONODE_ADDRESS, CONODE_PUBLIC_KEY_BYTE_ARRAY, CONODE_DESCRIPTION, CONODE_ID_UNDEFINED);

      serverIdentity.address.should.equal(CONODE_ADDRESS);
      serverIdentity.public.should.deep.equal(CONODE_PUBLIC_KEY_BYTE_ARRAY);
      serverIdentity.description.should.equal(CONODE_DESCRIPTION);
      serverIdentity.id.should.deep.equal(CONODE_ID_REAL_BYTE_ARRAY);
    });

    it("should correctly create a ServerIdentity", function () {
      const serverIdentity = Convert.toServerIdentity(CONODE_ADDRESS, CONODE_PUBLIC_KEY_BYTE_ARRAY, CONODE_DESCRIPTION, CONODE_ID_REAL_BYTE_ARRAY);

      serverIdentity.address.should.equal(CONODE_ADDRESS);
      serverIdentity.public.should.deep.equal(CONODE_PUBLIC_KEY_BYTE_ARRAY);
      serverIdentity.description.should.equal(CONODE_DESCRIPTION);
      serverIdentity.id.should.deep.equal(CONODE_ID_REAL_BYTE_ARRAY);
    });
  });

  describe("#publicKeyToUuid", function () {
    it("should throw an error when the input is not a byte array", function () {
      expect(() => Convert.publicKeyToUuid("CONODE_PUBLIC_KEY_BYTE_ARRAY")).to.throw();
    });

    it("should correctly convert a public key to uuid", function () {
      const uuid = Convert.publicKeyToUuid(CONODE_PUBLIC_KEY_BYTE_ARRAY);

      uuid.should.deep.equal(CONODE_ID_REAL_BYTE_ARRAY);
    });
  });

  describe("#parseJsonPopDesc", function () {
    it("should throw an error when the input is not a string", function () {
      expect(() => Convert.parseJsonPopDesc(FINAL_POP_DESC)).to.throw();
    });

    it("should return a PopDesc object", function () {
      const popDesc = Convert.parseJsonPopDesc(JSON.stringify(FINAL_POP_DESC));

      Helper.isOfType(popDesc, ObjectType.POP_DESC).should.be.true;
    });

    it("should correctly parse the JSON string into a PopDesc", function () {
      const popDesc = Convert.parseJsonPopDesc(JSON.stringify(FINAL_POP_DESC));

      popDesc.name.should.equal(FINAL_POP_DESC.name);
      popDesc.datetime.should.equal(FINAL_POP_DESC.datetime);
      popDesc.location.should.equal(FINAL_POP_DESC.location);

      popDesc.roster.id.should.deep.equal(FINAL_POP_DESC.roster.id);
      popDesc.roster.list.length.should.equal(FINAL_POP_DESC.roster.list.length);
      for (let i = 0; i < FINAL_POP_DESC.roster.list.length; ++i) {
        popDesc.roster.list[i].public.should.deep.equal(FINAL_POP_DESC.roster.list[i].public);
        popDesc.roster.list[i].id.should.deep.equal(FINAL_POP_DESC.roster.list[i].id);
        popDesc.roster.list[i].address.should.equal(FINAL_POP_DESC.roster.list[i].address);
        popDesc.roster.list[i].description.should.equal(FINAL_POP_DESC.roster.list[i].description);
      }
      popDesc.roster.aggregate.should.deep.equal(ROSTER_AGGREGATE_BYTE_ARRAY);
    });
  });

  describe("#parseJsonFinalStatement", function () {
    it("should throw an error when the input is not a string", function () {
      expect(() => Convert.parseJsonFinalStatement(FINAL_STATEMENT)).to.throw();
    });

    it("should return a FinalStatement object", function () {
      const finalStatement = Convert.parseJsonFinalStatement(JSON.stringify(FINAL_STATEMENT));

      Helper.isOfType(finalStatement, ObjectType.FINAL_STATEMENT).should.be.true;
    });

    it("should correctly parse the JSON string into a FinalStatement", function () {
      const finalStatement = Convert.parseJsonFinalStatement(JSON.stringify(FINAL_STATEMENT));

      finalStatement.attendees.length.should.equal(FINAL_STATEMENT.attendees.length);
      for (let i = 0; i < FINAL_STATEMENT.attendees.length; ++i) {
        finalStatement.attendees[i].should.deep.equal(FINAL_STATEMENT.attendees[i]);
      }

      finalStatement.signature.should.deep.equal(FINAL_STATEMENT.signature);
      finalStatement.merged.should.equal(FINAL_STATEMENT.merged);
    });
  });

  describe("#parseJsonPopToken", function () {
    it("should throw an error when the input is not a string", function () {
      expect(() => Convert.parseJsonPopToken(POP_TOKEN)).to.throw();
    });

    it("should return a PopToken object", function () {
      const popToken = Convert.parseJsonPopToken(JSON.stringify(POP_TOKEN));

      Helper.isOfType(popToken, ObjectType.POP_TOKEN).should.be.true;
    });

    it("should correctly parse the JSON string into a PopToken", function () {
      const popToken = Convert.parseJsonPopToken(JSON.stringify(POP_TOKEN));

      popToken.private.should.deep.equal(POP_TOKEN.private);
      popToken.public.should.deep.equal(POP_TOKEN.public);
    });
  });

  describe("#parseJsonFinalStatementsArray", function () {
    it("should throw an error when the input is not a string", function () {
      expect(() => Convert.parseJsonFinalStatementsArray("[FINAL_STATEMENT, FINAL_STATEMENT]")).to.throw();
    });

    it("should return an array of FinalStatements object", function () {
      const object = {};
      object.array = [FINAL_STATEMENT, FINAL_STATEMENT, FINAL_STATEMENT];

      const finalStatements = Convert.parseJsonFinalStatementsArray(JSON.stringify(object));

      Array.isArray(finalStatements).should.be.true;
      Helper.isOfType(finalStatements[0], ObjectType.FINAL_STATEMENT).should.be.true;
    });

    it("should correctly parse the JSON string into an array of FinalStatements", function () {
      const object = {};
      object.array = [FINAL_STATEMENT, FINAL_STATEMENT, FINAL_STATEMENT];

      const finalStatements = Convert.parseJsonFinalStatementsArray(JSON.stringify(object));

      finalStatements.length.should.equal(3);
    });
  });

  describe("#parseJsonPopTokenArray", function () {
    it("should throw an error when the input is not a string", function () {
      expect(() => Convert.parseJsonPopTokenArray("[POP_TOKEN, POP_TOKEN]")).to.throw();
    });

    it("should return an array of PopToken object", function () {
      const object = {};
      object.array = [POP_TOKEN, POP_TOKEN, POP_TOKEN];

      const popToken = Convert.parseJsonPopTokenArray(JSON.stringify(object));

      Array.isArray(popToken).should.be.true;
      Helper.isOfType(popToken[0], ObjectType.POP_TOKEN).should.be.true;
    });

    it("should correctly parse the JSON string into an array of  PopToken", function () {
      const object = {};
      object.array = [POP_TOKEN, POP_TOKEN, POP_TOKEN];

      const popToken = Convert.parseJsonPopTokenArray(JSON.stringify(object));

      popToken.length.should.equal(3);
    });
  });

  describe("#parseJsonPopDescHash", function () {
    it("should throw an error when the input is not a string", function () {
      expect(() => Convert.parseJsonPopDescHash(42)).to.throw();
    });

    it("should return a byte array", function () {
      const hash = Convert.parseJsonPopDescHash(POP_DESC_HASH_JSON);

      (hash instanceof Uint8Array).should.be.true;
    });

    it("should correctly parse the PopDesc hash", function () {
      const hash = Convert.parseJsonPopDescHash(POP_DESC_HASH_JSON);

      hash.should.deep.equal(PRIVATE_KEY_BYTE_ARRAY);
    });
  });

  describe("#parseJsonServerIdentity", function () {
    it("should throw an error when the input is not a string", function () {
      expect(() => Convert.parseJsonServerIdentity(42)).to.throw();
    });

    it("should return a ServerIdentity object", function () {
      const serverIdentity = Convert.parseJsonServerIdentity(SERVER_IDENTITY_JSON);

      Helper.isOfType(serverIdentity, ObjectType.SERVER_IDENTITY).should.be.true;
    });

    it("should correctly parse the server identity", function () {
      const serverIdentity = Convert.parseJsonServerIdentity(SERVER_IDENTITY_JSON);

      serverIdentity.address.should.equal(CONODE_ADDRESS);
      serverIdentity.public.should.deep.equal(CONODE_PUBLIC_KEY_BYTE_ARRAY);
      serverIdentity.description.should.equal(CONODE_DESCRIPTION);
      serverIdentity.id.should.deep.equal(CONODE_ID_REAL_BYTE_ARRAY);
    });
  });

  describe("#parseJsonArrayOfKeys", function () {
    it("should throw an error when the input is not a string", function () {
      expect(() => Convert.parseJsonArrayOfKeys(42)).to.throw();
    });

    it("should return an array of byte arrays", function () {
      const arrayOfKeys = Convert.parseJsonArrayOfKeys(ARRAY_OF_KEYS_JSON);

      Array.isArray(arrayOfKeys).should.be.true;
      (arrayOfKeys[0] instanceof Uint8Array).should.be.true;
    });

    it("should correctly parse the array of keys", function () {
      const arrayOfKeys = Convert.parseJsonArrayOfKeys(ARRAY_OF_KEYS_JSON);

      arrayOfKeys.forEach(byteArray => {
        byteArray.should.deep.equal(PUBLIC_KEY_BYTE_ARRAY);
      });
    });
  });
});
