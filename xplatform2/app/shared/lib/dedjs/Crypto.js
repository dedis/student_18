require("nativescript-nodeify");

const Convert = require("./Convert");
const CothorityMessages = require("./network/cothority-messages");
const Kyber = require("@dedis/kyber-js");
const ObservableModule = require("data/observable");
const FileIO = require("../file-io/file-io");
const FilesPath = require("../../res/files/files-path");

const CURVE_ED25519_KYBER = new Kyber.curve.edwards25519.Curve;


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
            toHex: Convert.byteArrayToHex
        });

        return this.load()
            .then(() => {
                return Promise.resolve(this);
            });
    }

    get public() {
        return this.getModule().public.slice(0);
    }

    get private() {
        return this.getModule().private.slice(0);
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
     * Sets the new key pair given in parameters.
     * @param {Uint8Array} publicKey - the new public key
     * @param {Uint8Array} privateKey - the new private key
     * @param {boolean} save - if the new key pair should be saved permanently
     * @returns {Promise} - a promise that gets resolved once the new key pair has been set and saved if the save parameter is set to true
     */
    setKeyPair(publicKey, privateKey, save) {
        if (!publicKey instanceof Uint8Array) {
            throw new Error("publicKey must be of type UInt8Array");
        }
        if (!privateKey instanceof Uint8Array) {
            throw new Error("privateKey must be of type UInt8Array");
        }
        if (typeof save !== "boolean") {
            throw new Error("save must be of type boolean");
        }

        const oldKeyPair = {
            public: this.public,
            private: this.private,
        };

        this.getModule().public = publicKey;
        this.getModule().private = privateKey;


        if (save) {
            let toWrite = "";
            if (publicKey.length > 0 && privateKey.length > 0) {
                toWrite = Convert.objectToJson({
                    public: Convert.byteArrayToBase64(publicKey),
                    private: Convert.byteArrayToBase64(privateKey),
                });
            }
            console.log("This is toWrite :****" + toWrite + "*****");


            return FileIO.writeStringTo(FileIO.join(this._dirname, FilesPath.KEY_PAIR), toWrite)
                .catch((error) => {
                    console.log(error);
                    console.dir(error);
                    console.trace();

                    return this.setKeyPair(oldKeyPair.public, oldKeyPair.private, false)
                        .then(() => {
                            return Promise.reject(error);
                        });
                });

        } else {
            return new Promise((resolve) => {
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

        return this.setKeyPair(pubKey.marshalBinary(), Convert.hexToByteArray(privateKey.toString()), true);
    }

    /**
     * Loads the keypair memory.
     * @returns {Promise} - a promise that gets resolved once the key pair is loaded into memory
     */
    load() {

        return FileIO.getStringOf(FileIO.join(this._dirname, FilesPath.KEY_PAIR))
            .then(jsonKeyPair => {
                if (jsonKeyPair.length > 0 && Convert.jsonToObject(jsonKeyPair).public !== ""
                    && Convert.jsonToObject(jsonKeyPair).private !== "" && Convert.jsonToObject(jsonKeyPair).private !== "") {
                    const parsed = Convert.parseJsonKeyPair(jsonKeyPair);
                    return this.setKeyPair(parsed.public, parsed.private, false);
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
        return this.setKeyPair(new Uint8Array([]), new Uint8Array([]), true)
            .catch(error => {
                console.log(error);
                console.dir(error);
                console.trace();

                return Promise.reject(error);
            });
    }
}

module.exports.aggregatePublicKeys = aggregatePublicKeys;
module.exports.KeyPair = KeyPair;

