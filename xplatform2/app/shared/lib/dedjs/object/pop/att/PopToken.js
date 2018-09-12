const Helper = require("../../../Helper");
const ObjectType = require("../../../ObjectType");

/**
 * This class represents a simple PoP-Token, that is the final statement of a party along
 * with the key pair of the user
 */
class PopToken {
    /**
     *
     * @param {FinalStatement} finalStatement - final statement of the party
     * @param {Uint8Array} privateKey - private key of the user
     * @param {Uint8Array} publicKey - public key of the user
     */
    constructor(finalStatement, privateKey, publicKey) {
        if(!Helper.isOfType(finalStatement, ObjectType.FINAL_STATEMENT)) {
            throw "finalStatement should be of type FinalStatement"
        }
        if(!(privateKey instanceof Uint8Array)) {
            throw "privateKey should be of type UInt8Array"
        }
        if(!(publicKey instanceof Uint8Array)) {
            throw "publicKey should be of type UInt8Array"
        }
        this.final = finalStatement;
        this.private = privateKey;
        this.public = publicKey;
    }
}

module.exports = PopToken;
