'use strict';

const DedisProtobuf = require("@dedis/cothority").protobuf;

/**
 * Base class for the protobuf library that provides helpers to encode and decode
 * messages according to a given model.
 *
 * @author Gaylor Bosson (gaylor.bosson@epfl.ch)
 * @author Cedric Maire (cedric.maire@epfl.ch)
 * @author Vincent Petri (vincent.petri@epfl.ch)
 */
class CothorityProtobuf {

  /**
   * @constructor
   */
  constructor() {
    this.root = DedisProtobuf.root;
  }

  /**
   * Returns the protobuf loaded model.
   * @param {string} name - the name of the model
   * @returns {ReflectionObject|?ReflectionObject|string} - the model
   */
  getModel(name) {
    if (typeof name !== "string") {
      throw new Error("name must be of type string");
    }

    const model = this.root.lookup(`${name}`);
    if (model === undefined || model === null) {
      throw new Error("unknown model: " + name);
    }

    return model;
  }
}

const Helper$1 = require("../Helper");
const ObjectType = require("../ObjectType");

/**
 * Helpers to encode and decode messages of the Cothority
 *
 * @author Gaylor Bosson (gaylor.bosson@epfl.ch)
 * @author Cedric Maire (cedric.maire@epfl.ch)
 * @author Vincent Petri (vincent.petri@epfl.ch)
 */
class CothorityMessages extends CothorityProtobuf {

  /**
   * Error return from the server when PIN is shown in the log
   *
   * @return {string} - the error
   */
  get READ_PIN_ERROR() {
    return 'Read PIN in server-log';
  }


  /**
   * Server related messages.
   */

  /**
   * Creates a ServerIdentity object from the given parameters.
   * @param {Uint8Array} publicKey - the public key of the conode
   * @param {Uint8Array} id - the id of the conode
   * @param {string} address - the address of the conode
   * @param {string} desc - the description of the conode
   * @returns {ServerIdentity} - the server identity object created from the parameters
   */
  createServerIdentity(publicKey, id, address, desc) {
    if (!(publicKey instanceof Uint8Array)) {
      throw new Error("publicKey must be an instance of Uint8Array");
    }
    if (!(id instanceof Uint8Array)) {
      throw new Error("id must be an instance of Uint8Array");
    }
    if (typeof address !== "string") {
      throw new Error("address must be of type string");
    }
    if (typeof desc !== "string") {
      throw new Error("desc must be of type string");
    }

    const model = this.getModel(ObjectType.SERVER_IDENTITY);

    const fields = {
      public: publicKey,
      id: id,
      address: address,
      description: desc
    };

    return model.create(fields);
  }

  /**
   * Creates a Roster object.
   * @param {Uint8Array} id - the id of the roster
   * @param {Array} list - array of ServerIdentity
   * @param {Uint8Array} aggregate - the aggregate of the conodes in list
   * @returns {Roster} - the roster object created form the parameters
   */
  createRoster(id, list, aggregate) {
    if (!(id === undefined || id instanceof Uint8Array)) {
      throw new Error("id must be an instance of Uint8Array or be undefined to skip it");
    }
    if (!(list instanceof Array)) {
      throw new Error("list must be an instance of Array");
    }
    if (list.length > 0 && !Helper$1.isOfType(list[0], ObjectType.SERVER_IDENTITY)) {
      throw new Error("list[i] must be an instance of ServerIdentity");
    }
    if (!(aggregate instanceof Uint8Array)) {
      throw new Error("aggregate must be an instance of Uint8Array");
    }

    const model = this.getModel(ObjectType.ROSTER);

    const fields = {
      list: list,
      aggregate: aggregate
    };

    if (id !== undefined) {
      fields.id = id;
    }

    return model.create(fields);
  }

  /**
   * Creates an message to make a StatusRequest to a cothority node.
   * @returns {*|Buffer|Uint8Array} - the status request
   */
  createStatusRequest() {
    return {};
  }

  /**
   * PoP related messages.
   */

  /**
   * Creates a PopDesc using the information given as parameters.
   * @param {string} name - the name of the pop party
   * @param {string} datetime - the date and time of the pop party
   * @param {string} location - the location of the pop party
   * @param {Roster} roster - the roster used to host the pop party
   * @returns {PopDesc} - the PopDesc object created using the given parameters
   */
  createPopDesc(name, datetime, location, roster) {
    if (typeof name !== "string") {
      throw new Error("name must be of type string");
    }
    if (typeof datetime !== "string") {
      throw new Error("datetime must be of type string");
    }
    if (typeof location !== "string") {
      throw new Error("location must be of type string");
    }
    if (!Helper$1.isOfType(roster, ObjectType.ROSTER)) {
      throw new Error("roster must be an instance of Roster");
    }

    const model = this.getModel(ObjectType.POP_DESC);

    const fields = {
      name: name,
      datetime: datetime,
      location: location,
      roster: roster
    };

    return model.create(fields);
  }

  /**
   * Creates an message to store configuration information of a given PoP party on a conode.
   * @param {PopDesc} desc - the pop description
   * @param {Uint8Array} signature - the signature of the message
   * @returns {{desc: *, signature: Uint8Array}} - the store config request
   */
  createStoreConfig(desc, signature) {
    if (!Helper$1.isOfType(desc, ObjectType.POP_DESC)) {
      throw new Error("desc must be an instance of PopDesc");
    }
    if (!(signature instanceof Uint8Array)) {
      throw new Error("signature must be an instance of Uint8Array");
    }
    /*
    if (desc.roster.id !== undefined) {
      delete desc.roster.id;
    }
    */

    const fields = {
      desc: desc,
      signature: signature
    };

    return fields;
  }

  /**
   * Creates a FinalStatement given the parameters.
   * @param {PopDesc} desc - the description of the pop party
   * @param {Array} attendees - all the attendees of the pop party
   * @param {Uint8Array} signature - the collective signature of the pop party
   * @param {boolean} merged - if the pop party has been merged
   * @returns {FinalStatement} - the final statement created given the parameters
   */
  createFinalStatement(desc, attendees, signature, merged) {
    if (!Helper$1.isOfType(desc, ObjectType.POP_DESC)) {
      throw new Error("desc must be an instance of PopDesc");
    }
    if (!(attendees instanceof Array)) {
      throw new Error("attendees must be an instance of Array");
    }
    if (attendees.length > 0 && !(attendees[0] instanceof Uint8Array)) {
      throw new Error("attendees[i] must be an instance of Uint8Array");
    }
    if (!(signature instanceof Uint8Array)) {
      throw new Error("signature must be an instance of Uint8Array");
    }
    if (typeof merged !== "boolean") {
      throw new Error("merged must be of type boolean");
    }

    const model = this.getModel(ObjectType.FINAL_STATEMENT);

    const fields = {
      desc: desc,
      attendees: attendees,
      signature: signature,
      merged: merged
    };

    return model.create(fields);
  }

  /**
   * Creates an message to finalize the pop party referenced by descId.
   * @param {Uint8Array} descId - the id of the config
   * @param {Array} attendees - the array containing all the public keys of the attendees
   * @param {Uint8Array} signature - the signature of the message
   * @returns {{descId: Uint8Array, attendees: Array, signature: Uint8Array}} - the finalize request
   */
  createFinalizeRequest(descId, attendees, signature) {
    if (!(descId instanceof Uint8Array)) {
      throw new Error("descId must be an instance of Uint8Array");
    }
    if (!(attendees instanceof Array)) {
      throw new Error("attendees must be an instance of Array");
    }
    if (attendees.length > 0 && !(attendees[0] instanceof Uint8Array)) {
      throw new Error("attendees[i] must be an instance of Uint8Array");
    }
    if (!(signature instanceof Uint8Array)) {
      throw new Error("signature must be an instance of Uint8Array");
    }

    const fields = {
      descid: descId,
      attendees: attendees,
      signature: signature
    };

    return fields;
  }

  /**
   * Creates a message to check a PoP Config status
   * @param hash - has of a party
   * @param attendees - array of attendees to the party
   * @returns {{hash: Uint8Array, attendees: Array}}
   */
  createCheckConfigRequest(hash, attendees) {
    if (!(hash instanceof Uint8Array)) {
      throw new Error("has must be an instance of Uint8Array");
    }
    if (!(attendees instanceof Array)) {
      throw new Error("attendees must be an instance of Array");
    }
    if (attendees.length > 0 && !(attendees[0] instanceof Uint8Array)) {
      throw new Error("attendees[i] must be an instance of Uint8Array");
    }

    const fields = {
      hash: hash,
      attendees: attendees
    }

    return fields;
  }

  /**
   * Creates an message to make a PinRequest to a cothority node.
   * @param {string} pin - previously generated by the conode
   * @param {Uint8Array} publicKey - the public key of the organizer
   * @returns {{pin: string, public: Uint8Array}} - the pin request
   */
  createPinRequest(pin, publicKey) {
    if (typeof pin !== "string") {
      throw new Error("pin must be of type string");
    }
    if (!(publicKey instanceof Uint8Array)) {
      throw new Error("publicKey must be an instance of Uint8Array");
    }

    const fields = {
      pin: pin,
      public: publicKey
    };

    return fields;
  }

  /**
   * Creates a messages to make a VerifyLink reuqest to a conode
   * @param {Uint8Array} publicKey - the public key of the user
   * @returns {{public: Uint8Array}} - the verify link request
   */
  createVerifyLinkMessage(publicKey) {
    if (!(publicKey instanceof Uint8Array)) {
      throw new Error("publicKey must be an instance of Uint8Array");
    }

    const fields = {
      public: publicKey
    };

    return fields;
  }

  /**
   * Creates an FetchRequest for the pop party referenced by id.
   * @param {Uint8Array} id - the id of the config
   * @param {boolean} returnUncomplete - a boolean to tell the conode if the final statement
   * should be return even if it is uncomplete
   * @returns {{id: Uint8Array, returnUncomplete: *}} - the fetch request
   */
  createFetchRequest(id, returnUncomplete) {
    if (!(id instanceof Uint8Array)) {
      throw new Error("id must be an instance of Uint8Array");
    }

    if (returnUncomplete !== undefined && typeof returnUncomplete !== "boolean") {
      throw new Error("returnUncomplete must be of type boolean or undefined but was " + typeof returnUncomplete);
    }


    const fields = {
      id: id,
      returnuncomplete: returnUncomplete
    };

    return fields;
  }

  /**
   * CISC related messages.
   */

  /**
   * Creates a Config object using the given parameters.
   * @param threshold
   * @param device
   * @param data
   * @returns {object} Config
   */
  createConfig(threshold, device, data) {
    const model = this.getModel("Config");

    const fields = {
      threshold: threshold,
      device: device,
      data: data
    };

    return model.create(fields);
  }

  /**
   * Create a message request to get the config of a given conode.
   * @param id
   * @returns {{id: *}}
   */
  createDataUpdate(id) {
    const fields = {
      id: id
    };

    return fields;
  }

  /**
   * Creates a SchnorrSig object using the given parameters.
   * @param challenge
   * @param response
   * @returns {object} SchnorrSig
   */
  createSchnorrSig(challenge, response) {
    const model = this.getModel("SchnorrSig");

    const fields = {
      challenge: challenge,
      response: response
    };

    return model.create(fields);
  }

  /**
   * Create a device structure, that may be added to a config.
   * @param key
   * @returns {fields}
   */
  createDevice(key) {
    const model = this.getModel("Device");

    const fields = {
      point: key
    };

    return model.create(fields);
  }

  /**
   * Create a message request to vote an update to a config.
   * @param id
   * @param signer
   * @param challenge
   * @param response
   * @returns {{id: *, signer: *, signature: *}}
   */
  createProposeVote(id, signer, signature) {
    const fields = {
      id: id,
      signer: signer,
      signature: signature
    };

    return fields;
  }

  /**
   * Create a message request to propose an update to a config.
   * @param id
   * @param config
   * @returns {{id: *, data: *}}
   */
  createProposeSend(id, data) {
    const fields = {
      id: id,
      data: data
    };

    return fields;
  }

  /**
   * Create a message request to get the current config update propositions.
   * @param id
   * @returns {{id: *}}
   */
  createProposeUpdate(id) {
    const fields = {
      id: id
    };

    return fields;
  }

}

/**
 * Singleton
 */
var index = new CothorityMessages();

module.exports = index;
