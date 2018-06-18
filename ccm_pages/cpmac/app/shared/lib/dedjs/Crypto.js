require("nativescript-nodeify");

const Convert = require("./Convert");
const CothorityMessages = require("./network/cothority-messages");
const Kyber = require("@dedis/kyber-js");
const ObservableModule = require("data/observable");
const Helper = require("./Helper");
const FileIO = require("../file-io/file-io");
const FilesPath = require("../../res/files/files-path");
const ObjectType = require("./ObjectType");

const CURVE_ED25519_KYBER = new Kyber.curve.edwards25519.Curve;

const EMPTY_KEYPAIR = CothorityMessages.createKeyPair(new Uint8Array(), new Uint8Array(), new Uint8Array());


/**
 * Computes the aggregate of a list of public keys (elliptic curve points).
 * @param {Array} points - array of public keys to aggregate (elliptic curve points)
 * @returns {Uint8Array} - the aggregate point as Uint8Array format
 */
function aggregatePublicKeys(points) {
  if (!(points instanceof Array)) {
    throw new Error("points must be an instance of Array");
  }
  if (points.length > 0 && points[0].constructor !== Kyber.curve.edwards25519.Point) {
    throw new Error("points[i] must be of type Point");
  } else if (points.length === 0) {
    throw new Error("points is an empty array");
  }

  const [head, ...tail] = points;

  let addition = head;
  for (let point of tail) {
    addition = CURVE_ED25519_KYBER.point().add(addition, point);
  }

  return addition.marshalBinary();
}

/**
 * Generates a random ED25519 key pair.
 * @returns {KeyPair} - the generated key pair
 */
function generateRandomKeyPair() {
  const privateKey = CURVE_ED25519_KYBER.newKey();
  const basePoint = CURVE_ED25519_KYBER.point().base();
  const pubKey = CURVE_ED25519_KYBER.point().mul(privateKey, basePoint);

  return CothorityMessages.createKeyPair(pubKey.marshalBinary(), Convert.hexToByteArray(privateKey.toString()), Convert.hexToByteArray(pubKey.toString()));
}

/**
 * This represent a cryptographic key pair (public key with private key)
 */
class KeyPair {
  /**
   * Constructor for the Org class.
   * @param {string} dirname - directory of the key pair data. If the data doesn't exist, a random key pair
   *  is generated. The key pair will be stored under dirname/keypair.json
   */
  constructor(dirname) {
    if (typeof dirname !== "string") {
      throw new Error("dirname should be of type string or undefined");
    }
    this._dirname = dirname;
    this._keyPair = ObservableModule.fromObject({
      public: new Uint8Array(),
      private: new Uint8Array(),
      publicComplete: new Uint8Array(),
      toHex: Convert.byteArrayToHex
    });

    this.load()
  }

  /**
   * Returns the observable key pair module.
   * @returns {ObservableModule} - the observable key pair module
   */
  getModule() {
    return this._keyPair;
  }

  /**
   * Returns wether the key pair  is set.
   * @returns {boolean} - true if and only if the key pair has been set
   */
  isSet() {
    const keyPairModule = this.getModule();

    return keyPairModule.public.length > 0 &&
      keyPairModule.private.length > 0;
  }

  /**
   * Gets the users key pair.
   * @returns {KeyPair} - a key pair object containg the keys of the user
   */
  getKeyPair() {
    let publicComplete = undefined;
    if (this.getModule().publicComplete.length > 0) {
      publicComplete = this.getModule().publicComplete;
    }

    return CothorityMessages.createKeyPair(this.getModule().public, this.getModule().private, publicComplete);
  }

  /**
   * Sets the new key pair given in parameters.
   * @param {KeyPair} keyPair - the new key pair to set
   * @param {boolean} save - if the new key pair should be saved permanently
   * @returns {Promise} - a promise that gets resolved once the new key pair has been set and saved if the save parameter is set to true
   */
  setKeyPair(keyPair, save) {
    if (!Helper.isOfType(keyPair, ObjectType.KEY_PAIR)) {
      throw new Error("keyPair must be an instance of KeyPair");
    }
    if (typeof save !== "boolean") {
      throw new Error("save must be of type boolean");
    }

    const oldKeyPair = this.getKeyPair();

    this.getModule().public = keyPair.public;
    this.getModule().private = keyPair.private;

    if (keyPair.publicComplete !== undefined) {
      this.getModule().publicComplete = keyPair.publicComplete;
    } else {
      this.getModule().publicComplete = new Uint8Array();
    }

    const newKeyPair = this.getKeyPair();

    if (save) {
      let toWrite = "";
      if (newKeyPair.public.length > 0 && newKeyPair.private.length > 0) {
        toWrite = Convert.objectToJson(newKeyPair);
      }

      return FileIO.writeStringTo(FileIO.join(this._dirname, FilesPath.KEY_PAIR), toWrite)
        .catch((error) => {
          console.log(error);
          console.dir(error);
          console.trace();

          return this.setKeyPair(oldKeyPair, false)
            .then(() => {
              return Promise.reject(error);
            });
        });
    } else {
      return new Promise((resolve, reject) => {
        resolve();
      });
    }
  }

  /**
   * Randomize the key pair
   * @returns {Promise} - a promise that get resolved once a random keypair has been generated and saved
   */
  randomize() {
    const privateKey = CURVE_ED25519_KYBER.newKey();
    const basePoint = CURVE_ED25519_KYBER.point().base();
    const pubKey = CURVE_ED25519_KYBER.point().mul(privateKey, basePoint);
    const keyPair = CothorityMessages.createKeyPair(pubKey.marshalBinary(), Convert.hexToByteArray(privateKey.toString()), Convert.hexToByteArray(pubKey.toString()));

    return this.setKeyPair(keyPair, true);
  }

  /**
   * Loads the keypair memory.
   * @returns {Promise} - a promise that gets resolved once the key pair is loaded into memory
   */
  load() {
    return FileIO.getStringOf(FileIO.join(this._dirname, FilesPath.KEY_PAIR))
      .then(jsonKeyPair => {
        if (jsonKeyPair.length > 0 && Convert.jsonToObject(jsonKeyPair).public !== "" 
            &&  Convert.jsonToObject(jsonKeyPair).private !== "" && Convert.jsonToObject(jsonKeyPair).private !== "" ) {
          return this.setKeyPair(Convert.parseJsonKeyPair(jsonKeyPair), false);
        } else {
          return this.randomize();
        }
      })

      .catch(error => {
        console.log(error);
        console.dir(error);
        console.trace();

        return Promise.reject(error);
      });
  }

  /**
   * Completely resets the keypair.
   * @returns {Promise} - a promise that gets completed once the keypair has been reset
   */
  reset() {
    return this.setKeyPair(EMPTY_KEYPAIR, true)
      .catch(error => {
        console.log(error);
        console.dir(error);
        console.trace();

        return Promise.reject(error);
      });
  }
}

module.exports.aggregatePublicKeys = aggregatePublicKeys;
module.exports.generateRandomKeyPair = generateRandomKeyPair;
module.exports.KeyPair = KeyPair;

