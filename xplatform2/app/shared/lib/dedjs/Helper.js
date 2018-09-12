require("nativescript-nodeify");
const Kyber = require("@dedis/kyber-js");
const CURVE_ED25519 = new Kyber.curve.edwards25519.Curve;

const PUBLIC_KEY_BYTE_LENGTH_31 = 31;
const PUBLIC_KEY_BYTE_LENGTH_32 = 32;

const BASE_URL_TLS = "tls://";
const URL_PORT_SPLITTER = ":";
const PORT_MIN = 0;
const PORT_MAX = 65535;

// Regex taken from: https://www.w3resource.com/javascript/form/ip-address-validation.php
const IP_REGEX = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

const ARRAY_REGEX = /Array/;

/**
 * Checks wether the object is of a specific type.
 * @param {*} object - the object we want to check the type of
 * @param {string} type - the type name
 * @returns {boolean} - true if and only if object has the type given as paramter
 */
function isOfType(object, type) {
  if (typeof type !== "string") {
    throw new Error("type must be of type string");
  }
  if (!(object !== undefined && typeof object === "object")) {
    return false;
  }

  return object.constructor.name === type;
}

/**
 * Checks wether the object received as parameter is an array (typed or not!).
 * @param {object} object - the object to test
 * @returns {boolean} - true if and only if the object is an array (typed or not!)
 */
function isArray(object) {
  if (!(object !== undefined && typeof object === "object")) {
    throw new Error("object must be of type object and not undefined");
  }

  const toString = Object.prototype.toString.call(object);

  return ARRAY_REGEX.test(toString);
}

/**
 * Checks wether the public key given as parameter has the right length/format.
 * @param {Uint8Array} publicKey - the public key to check
 * @returns {boolean} - true if and only if the key has the right lenght/format
 */
function isValidPublicKey(publicKey) {
  if (!(publicKey instanceof Uint8Array)) {
    throw new Error("publicKey must be an instance of Uint8Array");
  }

  if (publicKey.length === PUBLIC_KEY_BYTE_LENGTH_31 || publicKey.length === PUBLIC_KEY_BYTE_LENGTH_32) {
    try {
      const point = CURVE_ED25519.point();
      point.unmarshalBinary(publicKey);

      return point !== undefined;
    } catch (error) {
      console.log(error);
      console.dir(error);
      console.trace();

      return false;
    }
  }

  return false;
}

/**
 * Checks wether the address given as parameter has the right format.
 * @param {string} address - the address to check
 * @returns {boolean} - true if and only if the address has the right format
 */
function isValidAddress(address) {
  if (typeof address !== "string") {
    throw new Error("address must be of type string");
  }

  if (address.startsWith(BASE_URL_TLS)) {
    let [ip, ...array] = address.replace(BASE_URL_TLS, "").split(URL_PORT_SPLITTER);

    if (array.length === 1) {
      const port = parseInt(array[0]);

      // Port equal to PORT_MAX is not allowed since the port will be increased by one for the websocket url.
      return PORT_MIN <= port && port < PORT_MAX;
    }
  }

  return false;
}

/**
 * Deep copies an object (DOES NOT COPY FUNCTION PROPERTIES).
 * @param {object} object - the object to deep copy
 * @returns {object} - a copy of the object given as parameter
 */
function deepCopy(object) {
  if (typeof object !== "object") {
    throw new Error("object must be of type object");
  }

  return JSON.parse(JSON.stringify(object));
}

module.exports.isOfType = isOfType;
module.exports.isArray = isArray;
module.exports.isValidPublicKey = isValidPublicKey;
module.exports.isValidAddress = isValidAddress;
module.exports.deepCopy = deepCopy;
module.exports.BASE_URL_TLS = BASE_URL_TLS;
