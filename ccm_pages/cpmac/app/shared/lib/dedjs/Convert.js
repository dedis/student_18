require("nativescript-nodeify");
const Kyber = require("@dedis/kyber-js");
const CURVE_ED25519 = new Kyber.curve.edwards25519.Curve;

const Buffer = require("buffer/").Buffer;
const Helper = require("./Helper");
const ObjectType = require("./ObjectType");
const Crypto = require("./Crypto");
const TomlParser = require("toml");
const Tomlify = require('tomlify-j0.4');
const UUID = require("pure-uuid");
const CothorityMessages = require("./network/cothority-messages");

const HEX_KEYWORD = "hex";
const BASE64_KEYWORD = "base64";

const URL_PORT_SPLITTER = ":";
const BASE_URL_WS = "ws://";
const BASE_URL_TLS = "tls://";

const BASE_URL_CONODE_ID = "https://dedis.epfl.ch/id/";
const NAME_SPACE_URL = "ns:URL";
const UUID_VERSION = 5;

/**
 * Converts a byte array to it's hexadecimal string representation
 * @param {Uint8Array} byteArray - the byte array to convert
 * @returns {string} - the hexadecimal string
 */
function byteArrayToHex(byteArray) {
  if (!(byteArray instanceof Uint8Array)) {
    throw new Error("byteArray must be an instance of Uint8Array");
  }

  return Buffer.from(byteArray).toString(HEX_KEYWORD);
}

/**
 * Converts a hexadecimal string to it's byte array representation.
 * @param {string} hexString - the hexadecimal string to convert
 * @returns {Uint8Array} - the byte array
 */
function hexToByteArray(hexString) {
  if (typeof hexString !== "string") {
    throw new Error("hexString must be of type string");
  }

  const hexBuffer = Buffer.from(hexString, HEX_KEYWORD);

  return new Uint8Array(hexBuffer.buffer, hexBuffer.byteOffset, hexBuffer.byteLength / Uint8Array.BYTES_PER_ELEMENT);
}

/**
 * Converts a byte array to it's base64 string representation.
 * @param {Uint8Array} byteArray - the byte array to convert
 * @returns {string} - the base64 string
 */
function byteArrayToBase64(byteArray) {
  if (!(byteArray instanceof Uint8Array)) {
    throw new Error("byteArray must be an instance of Uint8Array");
  }

  const hexString = byteArrayToHex(byteArray);

  return hexToBase64(hexString);
}

/**
 * Converts a base64 string to it's byte array representation.
 * @param {string} base64String - the base64 string to convert
 * @returns {Uint8Array} - the byte array
 */
function base64ToByteArray(base64String) {
  if (typeof base64String !== "string") {
    throw new Error("base64String must be of type string");
  }

  const hexString = base64ToHex(base64String);

  return hexToByteArray(hexString);
}

/**
 * Converts a hexadecimal string into it's base64 string representation.
 * @param {string} hexString - the hexadecimal string to convert
 * @returns {string} - the base64 string
 */
function hexToBase64(hexString) {
  if (typeof hexString !== "string") {
    throw new Error("hexString must be of type string");
  }

  return Buffer.from(hexString, HEX_KEYWORD).toString(BASE64_KEYWORD);
}

/**
 * Converts a base64 string into it's hexadecimal string representation.
 * @param {string} base64String - the base64 string to convert
 * @returns {string} - the hexadecimal string
 */
function base64ToHex(base64String) {
  if (typeof base64String !== "string") {
    throw new Error("base64String must be of type string");
  }

  return Buffer.from(base64String, BASE64_KEYWORD).toString(HEX_KEYWORD);
}

/**
 * Converts an object into its JSON string representation.
 * @param {object} object - the object taht will be converted to a JSON string
 * @returns {string} - the JSON string representation
 */
function objectToJson(object) {
  if (!(object !== undefined && typeof object === "object" && !Helper.isArray(object))) {
    throw new Error("object must be of type object (not array!) and not undefined");
  }

  return JSON.stringify(object, undefined, 4);
}

/**
 * Converts a JSON string into a JavaScript object.
 * @param {string} jsonString - the JSON string to convert to an object
 * @returns {object} - the object created from the JSON string
 */
function jsonToObject(jsonString) {
  if (typeof jsonString !== "string") {
    throw new Error("jsonString must be of type string");
  }

  return JSON.parse(jsonString);
}

/**
 * Converts an object into its TOML string representation.
 * @param {object} object - the object to be converted into TOML representation
 * @returns {string} - the TOML string representing the object
 */
function objectToToml(object) {
  if (!(object !== undefined && typeof object === "object" && !Helper.isArray(object))) {
    throw new Error("object must be of type object (not array!) and not undefined");
  }

  return Tomlify.toToml(object, { space: 4 });
}

/**
 * Converts a TOML string into a JavaScript object.
 * @param {string} tomlString - the TOML string to be converted into an object
 * @returns {object} - the object parsed from the TOML string
 */
function tomlToObject(tomlString) {
  if (typeof tomlString !== "string") {
    throw new Error("tomlString must be of type string");
  }

  return TomlParser.parse(tomlString);
}

/**
 * Converts a JSON string into it's TOML string representation.
 * @param {string} jsonString - the JSON string to be converted into a TOML string
 * @returns {string} - the TOML string converted from the JSON string
 */
function jsonToToml(jsonString) {
  if (typeof jsonString !== "string") {
    throw new Error("jsonString must be of type string");
  }

  const object = jsonToObject(jsonString);

  return objectToToml(object);
}

/**
 * Converts a TOML string into it's JSON string representation.
 * @param {string} tomlString - the TOML string to be converted into a JSON string
 * @returns {string} - the JSON string converted from the TOML string
 */
function tomlToJson(tomlString) {
  if (typeof tomlString !== "string") {
    throw new Error("tomlString must be of type string");
  }

  const object = tomlToObject(tomlString);

  return objectToJson(object);
}

/**
 * Converts a TLS URL to a Wesocket URL and builds a complete URL with the path given as parameter.
 * @param {ServerIdentity|string} serverIdentity - the server identity to take the url from
 * @param {string} path - the path after the base url
 * @returns {string} - the builded websocket url
 */
function tlsToWebsocket(serverIdentity, path) {
  let address = "";
  if (Helper.isOfType(serverIdentity, ObjectType.SERVER_IDENTITY)) {
    address = serverIdentity.address
  } else if (typeof serverIdentity === "string") {
    address = serverIdentity;
  } else {
    throw new Error("serverIdentity must be of type ServerIdentity or string");
  }
  if (typeof path !== "string") {
    throw new Error("path must be of type string");
  }

  let [ip, port] = address.replace(BASE_URL_TLS, "").split(URL_PORT_SPLITTER);
  port = parseInt(port) + 1;

  return BASE_URL_WS + ip + URL_PORT_SPLITTER + port + path;
}

/**
 * Parses a JSON string into an array of PopToken objects. The JSON string has to respresent an object with a property called "array".
 * @param {string} jsonString - the JSON string to parse into an array of PopToken objects
 * @returns {Array} - the parsed array of PopToken objects
 */
function parseJsonPopTokenArray(jsonString) {
  if (typeof jsonString !== "string") {
    throw new Error("jsonString must be of type string");
  }

  const object = jsonToObject(jsonString);
  if (object.array === undefined || !Array.isArray(object.array)) {
    throw new Error("object.array is undefined or not an array");
  }

  object.array = object.array.map(element => {
    return parseJsonPopToken(objectToJson(element));
  });

  return object.array;
}

/**
 * Parses a JSON string into a PopToken object.
 * @param {string} jsonString - the JSON string to parse into a PopToken object
 * @returns {PopToken} - the parsed PopToken object
 */
function parseJsonPopToken(jsonString) {
  if (typeof jsonString !== "string") {
    throw new Error("jsonString must be of type string");
  }

  const object = jsonToObject(jsonString);

  object.final = parseJsonFinalStatement(objectToJson(object.final));

  return CothorityMessages.createPopToken(object.final, base64ToByteArray(object.private), base64ToByteArray(object.public));
}

/**
 * Parses a JSON string into an array of FinalStatement objects. The JSON string has to respresent an object with a property called "array".
 * @param {string} jsonString - the JSON string to parse into an array of FinalStatement objects
 * @returns {Array} - the parsed array of FinalStatement objects
 */
function parseJsonFinalStatementsArray(jsonString) {
  if (typeof jsonString !== "string") {
    throw new Error("jsonString must be of type string");
  }

  const object = jsonToObject(jsonString);
  if (object.array === undefined || !Array.isArray(object.array)) {
    throw new Error("object.array is undefined or not an array");
  }

  object.array = object.array.map(element => {
    return parseJsonFinalStatement(objectToJson(element));
  });

  return object.array;
}

/**
 * Parses a JSON string into a FinalStatement object.
 * @param {string} jsonString - the JSON string to parse into a FinalStatement object
 * @returns {FinalStatement} - the parsed FinalStatement object
 */
function parseJsonFinalStatement(jsonString) {
  if (typeof jsonString !== "string") {
    throw new Error("jsonString must be of type string");
  }

  const object = jsonToObject(jsonString);
  if (object.attendees === undefined || !Array.isArray(object.attendees)) {
    throw new Error("object.attendees is undefined or not an array");
  }

  object.attendees = object.attendees.map(base64String => {
    return base64ToByteArray(base64String.split(" ").join("+"));
  });
  object.signature = base64ToByteArray(object.signature.split(" ").join("+"));
  object.desc = parseJsonPopDesc(objectToJson(object.desc));

  return CothorityMessages.createFinalStatement(object.desc, object.attendees, object.signature, object.merged);
}

/**
 * Parses a JSON string into a PopDesc object.
 * @param {string} jsonString - the JSON string to parse into a PopDesc object
 * @returns {PopDesc} - the parsed PopDesc object
 */
function parseJsonPopDesc(jsonString) {
  if (typeof jsonString !== "string") {
    throw new Error("jsonString must be of type string");
  }

  const object = jsonToObject(jsonString);

  return CothorityMessages.createPopDesc(object.name, object.dateTime, object.location, parseJsonRoster(objectToJson(object.roster)));
}

/**
 * Parses a JSON string into a PopDesc hash. The JSON has to represent an object with a "hash" property containing a base64 encoded string.
 * @param {string} jsonString - the JSON string to parse into a PopDesc hash
 * @returns {Uint8Array} - the parsed PopDesc hash
 */
function parseJsonPopDescHash(jsonString) {
  if (typeof jsonString !== "string") {
    throw new Error("jsonString must be of type string");
  }

  const hash = jsonToObject(jsonString).hash;

  return base64ToByteArray(hash);
}

/**
 * Parses a JSON string into a Cisc username
 * @param {string} jsonString - the JSON string to parse into the Cisc username
 * @returns {String} - the parsed string for the username
 */ 
function parseJsonUserName(jsonString) {
  if (typeof jsonString !== "string") {
    throw new Error("jsonString must be of type string");
  }

  const name = jsonToObject(jsonString);

  return name.name;
}

/**
 * Parses a JSON string into a Roster object, if the ServerIdentities does not have an ID yet it will be computed.
 * @param {string} jsonString - the JSON string to parse into a Roster object
 * @returns {Roster} - the parsed Roster object
 */
function parseJsonRoster(jsonString) {
  if (typeof jsonString !== "string") {
    throw new Error("jsonString must be of type string");
  }

  const roster = jsonToObject(jsonString);
  if (roster.list === undefined || !Array.isArray(roster.list)) {
    throw new Error("roster.list is undefined or not an array");
  }

  let rosterId = roster.id;
  if (rosterId !== undefined) {
    rosterId = base64ToByteArray(rosterId.split(" ").join("+"));
  }

  let aggregate = (roster.aggregate === undefined) ? undefined : base64ToByteArray(roster.aggregate.split(" ").join("+"));

  const points = [];
  const list = roster.list.map((server) => {
    if (aggregate === undefined) {
      let point = CURVE_ED25519.point();
      point.unmarshalBinary(base64ToByteArray(server.public.split(" ").join("+")));
      points.push(point);
    }

    let serverId = server.id;
    if (serverId !== undefined) {
      serverId = base64ToByteArray(serverId.split(" ").join("+"));
    }

    return toServerIdentity(server.address, base64ToByteArray(server.public.split(" ").join("+")), server.description, serverId);
  });

  if (aggregate === undefined) {
    aggregate = Crypto.aggregatePublicKeys(points);
  }

  return CothorityMessages.createRoster(rosterId, list, aggregate);
}

/**
 * Parses a TOML string into a Roster object, if the ServerIdentities does not have an ID yet it will be computed.
 *
 * The TOML has to be in this format:
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
  "  Description = \"Conode_3\""
 *
 * @param {string} tomlString - the TOML string to parse into a Roster object
 * @returns {Roster} - the parsed Roster object
 */
function parseTomlRoster(tomlString) {
  if (typeof tomlString !== "string") {
    throw new Error("tomlString must be of type string");
  }

  const roster = tomlToObject(tomlString);
  if (roster.servers === undefined) {
    throw new Error("roster.servers is undefined");
  }

  roster.servers.forEach(server => {
    Object.getOwnPropertyNames(server).forEach((propertyName, index, array) => {
      const lowerCased = propertyName.toLocaleLowerCase();

      if (lowerCased !== propertyName) {
        server[lowerCased] = server[propertyName];
        delete server[propertyName];
      }
    });
  });

  roster.list = [];
  roster.servers.forEach(server => {
    roster.list.push(Helper.deepCopy(server));
  });
  delete roster.servers;

  return parseJsonRoster(JSON.stringify(roster));
}

/**
 * Parses a JSON string into a KeyPair object.
 * @param {string} jsonString - the JSON string to parse into a KeyPair object
 * @returns {KeyPair} - the parsed KeyPair object
 */
function parseJsonKeyPair(jsonString) {
  if (typeof jsonString !== "string") {
    throw new Error("jsonString must be of type string");
  }

  const keyPair = jsonToObject(jsonString);

  let publicComplete = undefined;
  if (keyPair.publicComplete !== undefined) {
    publicComplete = base64ToByteArray(keyPair.publicComplete);
  }

  if (keyPair.private === undefined) {
    keyPair.private = "";
  }

  return CothorityMessages.createKeyPair(base64ToByteArray(keyPair.public), base64ToByteArray(keyPair.private), publicComplete);
}

/**
 * Parses a JSON string into a ServerIdentity object.
 * @param {string} jsonString - the JSON string to parse into a ServerIdentity object
 * @returns {ServerIdentity} - the parsed ServerIdentity object
 */
function parseJsonServerIdentity(jsonString) {
  if (typeof jsonString !== "string") {
    throw new Error("jsonString must be of type string");
  }

  const serverIdentity = jsonToObject(jsonString);

  const publicKey = base64ToByteArray(serverIdentity.public);
  const id = base64ToByteArray(serverIdentity.id);

  return toServerIdentity(serverIdentity.address, publicKey, serverIdentity.description, id);
}

/**
 * Parses a JSON string into an array of Uint8Array. The JSON has to represent an object with a "array" property that is an array of base64 encoded strings.
 * @param {string} jsonString - the JSON string to parse into an array of Uint8Array
 * @returns {Array} - the parsed an array of Uint8Array
 */
function parseJsonArrayOfKeys(jsonString) {
  if (typeof jsonString !== "string") {
    throw new Error("jsonString must be of type string");
  }

  let array = jsonToObject(jsonString).array;
  if (array === undefined || !Array.isArray(array)) {
    throw new Error("object.array is undefined or not an array");
  }

  array = array.map(base64String => {
    return base64ToByteArray(base64String);
  });

  return array;
}

/**
 * Converts the arguments given as parameter into a ServerIdentity object.
 * @param {string} address - the address of the server
 * @param {Uint8Array} publicKey - the public key of the server
 * @param {string} description - the description of the server
 * @param {Uint8Array} id - the id of the server or undefined to be skipped
 * @returns {ServerIdentity} - the server identity object created from the given parameters
 */
function toServerIdentity(address, publicKey, description, id) {
  if (typeof address !== "string" || !Helper.isValidAddress(address)) {
    throw new Error("address must be of type string and have the right format");
  }
  if (!(publicKey instanceof Uint8Array) || !Helper.isValidPublicKey(publicKey)) {
    throw new Error("publicKey must be an instance of Uint8Array and have the right format");
  }
  if (typeof description !== "string") {
    throw new Error("description must be of type string");
  }
  if (!(id === undefined || id instanceof Uint8Array)) {
    throw new Error("id must be an instance of Uint8Array or be undefined to be skipped");
  }

  if (id === undefined) {
    id = publicKeyToUuid(publicKey);
  }

  return CothorityMessages.createServerIdentity(publicKey, id, address, description);
}

/**
 * Converts a public key into a UUID. This UUID can then be used to uniquely identify the conode.
 * @param {Uint8Array} publicKey - the public key of the server
 * @returns {Uint8Array} - the uuid of the server
 */
function publicKeyToUuid(publicKey) {
  if (!(publicKey instanceof Uint8Array)) {
    throw new Error("publicKey must be an instance of Uint8Array");
  }

  const url = BASE_URL_CONODE_ID + byteArrayToHex(publicKey);

  return new Uint8Array(new UUID(UUID_VERSION, NAME_SPACE_URL, url).export());
}

module.exports.byteArrayToHex = byteArrayToHex;
module.exports.hexToByteArray = hexToByteArray;
module.exports.byteArrayToBase64 = byteArrayToBase64;
module.exports.base64ToByteArray = base64ToByteArray;
module.exports.hexToBase64 = hexToBase64;
module.exports.base64ToHex = base64ToHex;
module.exports.objectToJson = objectToJson;
module.exports.jsonToObject = jsonToObject;
module.exports.objectToToml = objectToToml;
module.exports.tomlToObject = tomlToObject;
module.exports.jsonToToml = jsonToToml;
module.exports.tomlToJson = tomlToJson;
module.exports.tlsToWebsocket = tlsToWebsocket;
module.exports.parseJsonPopTokenArray = parseJsonPopTokenArray;
module.exports.parseJsonPopToken = parseJsonPopToken;
module.exports.parseJsonFinalStatementsArray = parseJsonFinalStatementsArray;
module.exports.parseJsonFinalStatement = parseJsonFinalStatement;
module.exports.parseJsonPopDesc = parseJsonPopDesc;
module.exports.parseJsonPopDescHash = parseJsonPopDescHash;
module.exports.parseJsonUserName = parseJsonUserName;
module.exports.parseJsonRoster = parseJsonRoster;
module.exports.parseTomlRoster = parseTomlRoster;
module.exports.parseJsonKeyPair = parseJsonKeyPair;
module.exports.parseJsonServerIdentity = parseJsonServerIdentity;
module.exports.parseJsonArrayOfKeys = parseJsonArrayOfKeys;
module.exports.toServerIdentity = toServerIdentity;
module.exports.publicKeyToUuid = publicKeyToUuid;
