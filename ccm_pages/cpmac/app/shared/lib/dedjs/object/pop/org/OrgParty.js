require("nativescript-nodeify");

const Kyber = require("@dedis/kyber-js");
const Schnorr = Kyber.sign.schnorr;
const CURVE_ED25519_KYBER = new Kyber.curve.edwards25519.Curve;
const ObservableModule = require("data/observable");
const ObservableArray = require("data/observable-array").ObservableArray;
const HashJs = require("hash.js");
const Convert = require("../../../Convert");
const Helper = require("../../../Helper");
const ObjectType = require("../../../ObjectType");
const Net = require("@dedis/cothority").net;
const FilesPath = require("../../../../../res/files/files-path");
const FileIO = require("../../../../../lib/file-io/file-io");
const CothorityMessages = require("../../../network/cothority-messages");
const RequestPath = require("../../../network/RequestPath");
const DecodeType = require("../../../network/DecodeType");
const uuidv4 = require("uuid/v4");
const Party = require("../Party");

const User = require("../../user/User").get;
const PoP = require("../../pop/PoP").get;

/**
 * This class represents the organizer of a PoP party. It contains everything related to the organizer party.
 */
const EMPTY_SERVER_IDENTITY = CothorityMessages.createServerIdentity(new Uint8Array(), new Uint8Array(), "", "");
const EMPTY_ROSTER = CothorityMessages.createRoster(new Uint8Array(), [], new Uint8Array());
const EMPTY_POP_DESC = CothorityMessages.createPopDesc("", "", "", EMPTY_ROSTER);

class OrgParty extends Party {


  /**
   * Constructor for the Org class.
   * @param {string} [dirname] - directory of the party data (directory is created if non existent).
   *  If no directory is specified, a unique random directory name is generated
   */
  constructor(dirname) {
    super();
    if (typeof dirname === "string") {
      this._dirname = dirname;
    } else if (dirname === undefined) {
      this._dirname = uuidv4();
    } else {
      throw new Error("dirname should be of type string or undefined");
    }
    this._isLoaded = false;
    this._linkedConode = ObservableModule.fromObject({
      public: new Uint8Array(),
      id: new Uint8Array(),
      address: "",
      description: ""
    });
    this._registeredAtts = ObservableModule.fromObject({
      array: new ObservableArray()
    });
    this._popDescHash = ObservableModule.fromObject({
      hash: new Uint8Array()
    });
    this._status = ObservableModule.fromObject({
      status: States.UNDEFINED
    });

    this.load();
  }

  /**
   * Getters and Setters.
   */

  /**
   * Gets the isLoaded property of the organizer. It is only true once all the settings have been loaded into memory.
   * @returns {boolean} - a boolean that is true once the organizer has completely been loaded into memory
   */
  isLoaded() {
    return this._isLoaded;
  }

  /**
   * Returns the observable module for the linked conode.
   * @returns {ObservableModule} - the observable module for the conode
   */
  getLinkedConodeModule() {
    return this._linkedConode;
  }

  /**
   * Returns the server identity representing the conode the organizer is linked to.
   * @returns {ServerIdentity} - the ServerIdentity object the organizer is linked to
   */
  getLinkedConode() {
    const linkedConodeModule = this.getLinkedConodeModule();

    return CothorityMessages.createServerIdentity(linkedConodeModule.public, linkedConodeModule.id, linkedConodeModule.address, linkedConodeModule.description);
  }

  /**
   * Returns wether the linked conode is set.
   * @returns {boolean} - true if and only if the linked conode has been set
   */
  isLinkedConodeSet() {
    const linkedConodeModule = this.getLinkedConodeModule();

    return linkedConodeModule.public.length > 0 &&
      linkedConodeModule.id.length > 0 &&
      linkedConodeModule.address.length > 0 &&
      linkedConodeModule.description.length > 0;
  }

  /**
   * Sets the new conode given as parameter as linked conode.
   * @param {ServerIdentity} conode - the new conode to set as linked conode
   * @param {boolean} save - if the new conode should be saved permanently
   * @returns {Promise} - a promise that gets resolved once the new conode has been set and saved if the save parameter is set to true
   */
  setLinkedConode(conode, save) {
    if (!Helper.isOfType(conode, ObjectType.SERVER_IDENTITY)) {
      throw new Error("conode must be an instance of ServerIdentity");
    }
    if (typeof save !== "boolean") {
      throw new Error("save must be of type boolean");
    }

    const oldLinkedConode = this.getLinkedConode();

    const linkedConodeModule = this.getLinkedConodeModule();
    linkedConodeModule.public = Uint8Array.from(conode.public);
    linkedConodeModule.id = Uint8Array.from(conode.id);
    linkedConodeModule.address = conode.address;
    linkedConodeModule.description = conode.description;

    const newLinkedConode = this.getLinkedConode();

    if (save) {
      let toWrite = "";
      if (this.isLinkedConodeSet()) {
        toWrite = Convert.objectToJson(newLinkedConode);
      }

      return FileIO.writeStringTo(FileIO.join(FilesPath.POP_ORG_PATH, this._dirname, FilesPath.POP_ORG_CONODE), toWrite)
        .catch((error) => {
          console.log(error);
          console.dir(error);
          console.trace();

          return this.setLinkedConode(oldLinkedConode, false)
            .then(() => {
              return Promise.reject(error);
            });
        }).then(() => {
          return this.loadStatus();
        });
    } else {
      return new Promise((resolve, reject) => {
        resolve();
      });
    }
  }


  /**
   * Returns wether the PopDesc is being set (partially or completely).
   * @returns {boolean} - true if and only if the PopDesc is being set
   */
  isPopDescBeingSet() {
    const popDescModule = this.getPopDescModule();

    return popDescModule.name.length > 0 ||
      popDescModule.dateTime.length > 0 ||
      popDescModule.location.length > 0 ||
      popDescModule.roster.list.length > 0;
  }

  /**
   * Returns wether the PopDesc is complete.
   * @returns {boolean} - true if and only if the PopDesc is complete
   */
  isPopDescComplete() {
    const popDescModule = this.getPopDescModule();

    return popDescModule.name.length > 0 &&
      popDescModule.dateTime.length > 0 &&
      popDescModule.location.length > 0 &&
      popDescModule.roster.list.length >= 3;
  }

  /**
   * Sets the pop description.
   * @param {PopDesc} popDesc - the new pop description to set
   * @param {boolean} save - if the new pop description should be saved permanently
   * @returns {Promise} - a promise that gets resolved once the new pop description has been set and saved if the save parameter is set to true
   */
  setPopDesc(popDesc, save) {
    if (!Helper.isOfType(popDesc, ObjectType.POP_DESC)) {
      throw new Error("popDesc must be an instance of PopDesc");
    }
    if (typeof save !== "boolean") {
      throw new Error("save must be of type boolean");
    }

    const oldPopDesc = this.getPopDesc();

    const popDescModule = this.getPopDescModule();

    popDescModule.name = popDesc.name;
    popDescModule.dateTime = popDesc.dateTime;
    popDescModule.location = popDesc.location;
    popDescModule.roster.id = Uint8Array.from(popDesc.roster.id);

    this.emptyPopDescRosterList();
    popDesc.roster.list.forEach(server => {
      server.toHex = Convert.byteArrayToHex;
      popDescModule.roster.list.push(server);
    });

    popDescModule.roster.aggregate = Uint8Array.from(popDesc.roster.aggregate);

    const newPopDesc = this.getPopDesc();

    if (save) {
      let toWrite = "";
      if (this.isPopDescBeingSet()) {
        toWrite = Convert.objectToJson(newPopDesc);
      }

      return FileIO.writeStringTo(FileIO.join(FilesPath.POP_ORG_PATH, this._dirname, FilesPath.POP_ORG_DESC), toWrite)
        .catch((error) => {
          console.log(error);
          console.dir(error);
          console.trace();

          return this.setPopDesc(oldPopDesc, false)
            .then(() => {
              return Promise.reject(error);
            });
        })
        .then(() => {
          return this.updatePopHash();
        });
    } else {
      return new Promise((resolve, reject) => {
        resolve();
      });
    }
  }

  /**
   * Returns the observable module for the registered attendees.
   * @returns {ObservableModule} - the observable module for the registered attendees
   */
  getRegisteredAttsModule() {
    return this._registeredAtts;
  }

  /**
   * Returns the registered attendees.
   * @returns {ObservableArray} - the registered attendees
   */
  getRegisteredAtts() {
    return this.getRegisteredAttsModule().array;
  }

  /**
   * Sets the registered attendees array.
   * @param {Array} array - the new array of attendees to set
   * @param {boolean} save - if the new array of attendees should be saved permanently
   * @returns {Promise} - a promise that gets resolved once the new array of attendees has been set and saved if the save parameter is set to true
   */
  setRegisteredAtts(array, save) {
    if (!(array instanceof Array)) {
      throw new Error("array must be an instance of Array");
    }
    if (array.length > 0 && !(array[0] instanceof Uint8Array)) {
      throw new Error("array[i] must be an instance of Uint8Array or be empty");
    }
    if (typeof save !== "boolean") {
      throw new Error("save must be of type boolean");
    }

    const oldRegisteredAtts = this.getRegisteredAtts().slice();

    this.emptyRegisteredAttsArray();
    array.forEach(publicKey => {
      publicKey.toHex = Convert.byteArrayToHex;
      this.getRegisteredAtts().push(publicKey);
    });

    const newRegisteredAtts = this.getRegisteredAtts().slice();

    if (save) {
      let toWrite = "";
      if (newRegisteredAtts.length > 0) {
        const object = {};
        object.array = newRegisteredAtts.map(byteArray => {
          return Convert.byteArrayToBase64(byteArray);
        });

        toWrite = Convert.objectToJson(object);
      }

      return FileIO.writeStringTo(FileIO.join(FilesPath.POP_ORG_PATH, this._dirname, FilesPath.POP_ORG_ATTENDEES), toWrite)
        .catch((error) => {
          console.log(error);
          console.dir(error);
          console.trace();

          return this.setRegisteredAtts(oldRegisteredAtts, false)
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
   * Returns the observable module for the pop description hash.
   * @returns {ObservableModule} - the observable module for the pop description hash
   */
  getPopDescHashModule() {
    return this._popDescHash;
  }

  /**
   * Returns the pop description hash.
   * @returns {Uint8Array} - the pop description hash
   */
  getPopDescHash() {
    return this.getPopDescHashModule().hash;
  }

  /**
   * Returns the pop status observable module
   * @returns {ObservableModule}
   */
  getPopStatusModule() {
    return this._status;
  }

  /**
   * Returns the status of the party
   * @returns {string} - value of the enum States
   */
  getPopStatus() {
    return this.getPopStatusModule().status;
  }

  /**
   * Sets the pop description hash.
   * @param {Uint8Array} hash - the new hash to set
   * @param {boolean} save - if the new hash should be saved permanently
   * @returns {Promise} - a promise that gets resolved once the new hash has been set and saved if the save parameter is set to true
   */
  setPopDescHash(hash, save) {
    if (!(hash instanceof Uint8Array)) {
      throw new Error("hash must be an instance of Uint8Array");
    }
    if (typeof save !== "boolean") {
      throw new Error("save must be of type boolean");
    }

    const oldHash = this.getPopDescHash();

    this.getPopDescHashModule().hash = Uint8Array.from(hash);

    const newHash = this.getPopDescHash();

    if (save) {
      let toWrite = "";
      if (newHash.length > 0) {
        const object = {};
        object.hash = Convert.byteArrayToBase64(newHash);

        toWrite = Convert.objectToJson(object);
      }

      return FileIO.writeStringTo(FileIO.join(FilesPath.POP_ORG_PATH, this._dirname, FilesPath.POP_ORG_DESC_HASH), toWrite)
        .catch((error) => {
          console.log(error);
          console.dir(error);
          console.trace();

          return this.setPopDescHash(oldHash, false)
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
   * Action functions.
   */

  /**
   * Empties the registered attendees list. This action is not stored permanently.
   */
  emptyRegisteredAttsArray() {
    while (this.getRegisteredAtts().length > 0) {
      this.getRegisteredAtts().pop();
    }
  }

  /**
   * Empties the roster list of the pop description. This action is not stored permanently.
   */
  emptyPopDescRosterList() {
    while (this.getPopDescModule().roster.list.length > 0) {
      this.getPopDescModule().roster.list.pop();
    }
  }

  /**
   * Set the status of the party
   * @param {string} status - a value inside the Enum States
   */
  setPopStatus(status) {
    if (!Object.values(States).includes(status)) {
      throw new Error("status should be in enum States");
    }

    this.getPopStatusModule().status = status;
  }

  /**
   * Sets the name of the PopDesc.
   * @param {string} name - the new name of the PopDesc
   * @returns {Promise} - a promise that gets completed once the name of the PopDesc has been set
   */
  setPopDescName(name) {
    if (typeof name !== "string") {
      throw new Error("name must be of type string");
    }

    const popDesc = this.getPopDesc();
    popDesc.name = name;

    return this.setPopDesc(popDesc, true);
  }

  /**
   * Sets the date and time of the PopDesc.
   * @param {string} dateTime - the new date and time of the PopDesc
   * @returns {Promise} - a promise that gets completed once the date and time of the PopDesc has been set
   */
  setPopDescDateTime(dateTime) {
    if (typeof dateTime !== "string") {
      throw new Error("dateTime must be of type string");
    }

    const popDesc = this.getPopDesc();
    popDesc.dateTime = dateTime;

    return this.setPopDesc(popDesc, true);
  }

  /**
   * Sets the location of the PopDesc.
   * @param {string} location - the new location of the PopDesc
   * @returns {Promise} - a promise that gets completed once the location of the PopDesc has been set
   */
  setPopDescLocation(location) {
    if (typeof location !== "string") {
      throw new Error("location must be of type string");
    }

    const popDesc = this.getPopDesc();
    popDesc.location = location;

    return this.setPopDesc(popDesc, true);
  }

  /**
   * Adds a conode to the roster of the PopDesc.
   * @param {ServerIdentity} conode - the new conode to add to the PopDesc roster
   * @returns {Promise} - a promise that gets completed once the conode has been added to the PopDesc roster
   */
  addPopDescConode(conode) {
    if (!Helper.isOfType(conode, ObjectType.SERVER_IDENTITY)) {
      throw new Error("conode must be an instance of ServerIdentity");
    }

    let newRoster = {
      list: this.getPopDesc().roster.list
    };
    newRoster.list.push(conode);
    newRoster = Convert.parseJsonRoster(Convert.objectToJson(newRoster));

    const newPopDesc = this.getPopDesc();
    newPopDesc.roster = newRoster;

    return this.setPopDesc(newPopDesc, true);
  }

  /**
   * Removes the conode at the index given as parameter from the roster of the PopDesc.
   * @param {number} index - the index of the conode to remove from the PopDesc roster
   * @returns {Promise} - a promise that gets completed once the conode at the index given as parameter has been removed from the PopDesc roster
   */
  removePopDescConodeByIndex(index) {
    if (typeof index !== "number" || !(0 <= index && index < this.getPopDescModule().roster.list.length)) {
      throw new Error("index must be of type number and be in the right range");
    }

    let newRoster = {
      list: []
    };
    for (let i = 0; i < this.getPopDescModule().roster.list.length; ++i) {
      if (i !== index) {
        newRoster.list.push(this.getPopDescModule().roster.list.getItem(i));
      }
    }

    if (newRoster.list.length > 0) {
      newRoster = Convert.parseJsonRoster(Convert.objectToJson(newRoster));
    } else {
      newRoster = EMPTY_ROSTER;
    }

    const newPopDesc = this.getPopDesc();
    newPopDesc.roster = newRoster;

    return this.setPopDesc(newPopDesc, true);
  }

  /**
   * Registers the public key of the attendee.
   * @param {Uint8Array} publicKey - the public key of the attendee
   * @returns {Promise} - a promise that gets completed once the attendee has been registered
   */
  registerAttendee(publicKey) {
    if (!(publicKey instanceof Uint8Array) || !Helper.isValidPublicKey(publicKey)) {
      throw new Error("publicKey must be an instance of Uint8Array and have the right format");
    }

    const newAttendees = this.getRegisteredAtts().slice();
    newAttendees.push(publicKey);

    return this.setRegisteredAtts(newAttendees, true);
  }

  /**
   * Unregisters the public key of the attendee corresponding to the given index.
   * @param {number} index - the index of the public key to unregister
   * @returns {Promise} - a promise that gets completed once the attendee has been unregistered
   */
  unregisterAttendeeByIndex(index) {
    if (typeof index !== "number" || !(0 <= index && index < this.getRegisteredAtts().length)) {
      throw new Error("index must be of type number and be in the right range");
    }

    const newAttendees = [];
    for (let i = 0; i < this.getRegisteredAtts().length; ++i) {
      if (i !== index) {
        newAttendees.push(this.getRegisteredAtts().getItem(i));
      }
    }

    return this.setRegisteredAtts(newAttendees, true);
  }

  /**
   * Sends a link request to the conode given as parameter. If the pin is not empty and the link request succeeds
   * or if the public key of the user is already registered, the conode will be stored as the linked conode.
   * @param {ServerIdentity} conode - the conode to which send the link request
   * @param {string} pin - the pin received from the conode
   * @returns {Promise} - a promise that gets completed once the link request has been sent and a response received
   * @property {boolean} alreadyLinked -  a property of the object returned by the promise that tells if
   * the public key of the user were already registered (thus it won't need to ask PIN in the future)
   */
  linkToConode(conode, pin) {
    if (!Helper.isOfType(conode, ObjectType.SERVER_IDENTITY)) {
      throw new Error("conode must be an instance of ServerIdentity");
    }
    if (typeof pin !== "string") {
      throw new Error("pin must be of type string");
    }
    if (!User.isKeyPairSet()) {
      throw new Error("user should generate a key pair before linking to a conode");
    }
    const ALREADY_LINKED = "ALREADY_LINKED_STRING";
    const cothoritySocket = new Net.Socket(Convert.tlsToWebsocket(conode, ""), RequestPath.POP);
    const pinRequestMessage = CothorityMessages.createPinRequest(pin, User.getKeyPair().public);
    const verifyLinkMessage = CothorityMessages.createVerifyLinkMessage(User.getKeyPair().public);

    // TODO change status request return type

    return cothoritySocket.send(RequestPath.POP_VERIFY_LINK, DecodeType.VERIFY_LINK_REPLY, verifyLinkMessage)
      .then(alreadyLinked => {
        return alreadyLinked.exists ?
          Promise.resolve(ALREADY_LINKED) :
          cothoritySocket.send(RequestPath.POP_PIN_REQUEST, RequestPath.STATUS_REQUEST, pinRequestMessage)
      })
      .then(response => {
        return this.setLinkedConode(conode, true)
          .then(() => {
            const fields = {
              alreadyLinked: response === ALREADY_LINKED
            };
            return Promise.resolve(fields);
          })

      })
      .catch(error => {
        if (error.message === CothorityMessages.READ_PIN_ERROR) {
          return Promise.resolve(error.message)
        }
        console.log(error);
        console.dir(error);
        console.trace();

        return Promise.reject(error);
      });
  }

  /**
   * Update the hash of the party using current stored informations
   * @returns {Promise<Uint8Array>} - a promise that gets completed once the hash of the PopDesc has been saved
   */
  updatePopHash() {
    const popDesc = this.getPopDesc();
    const descHash = popDesc === {} ? [] : Convert.hexToByteArray(HashJs.sha256()
      .update(popDesc.name)
      .update(popDesc.dateTime)
      .update(popDesc.location)
      .update(popDesc.roster.aggregate)
      .digest("hex"));

    return this.setPopDescHash(descHash, true);
  }

  /**
   * Registers the local PopDesc on the linked conode. On success this will save the hash of the PopDesc for further usage.
   * @returns {Promise} - a promise that gets completed once the party has been registered
   */
  registerPopDesc() {
    if (!User.isKeyPairSet()) {
      throw new Error("user should generate a key pair before linking to a conode");
    }
    if (!this.isPopDescComplete()) {
      throw new Error("organizer should complete the PopDesc first");
    }
    if (!this.isLinkedConodeSet()) {
      throw new Error("organizer should link to his conode first");
    }

    const popDesc = this.getPopDesc();
    const descHash = this.getPopDescHash();

    const privateKey = CURVE_ED25519_KYBER.scalar();
    privateKey.unmarshalBinary(User.getKeyPair().private);
    const signature = Schnorr.sign(CURVE_ED25519_KYBER, privateKey, descHash);

    const cothoritySocket = new Net.Socket(Convert.tlsToWebsocket(this.getLinkedConode(), ""), RequestPath.POP);
    const storeConfigMessage = CothorityMessages.createStoreConfig(popDesc, signature);

    return cothoritySocket.send(RequestPath.POP_STORE_CONFIG, DecodeType.STORE_CONFIG_REPLY, storeConfigMessage)
      .then(response => {
        if (Convert.byteArrayToBase64(response.id) === Convert.byteArrayToBase64(descHash)) {
          return Promise.resolve(descHash);
        } else {
          return Promise.reject("hash was different");
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
   * Registers the attendees to the PoP-Party stored on the linked conode, this finalizes the party.
   * @returns {Promise<string>} - a promise that gets completed once the attendees have been registered
   * and the party finalized. The Promise conatins the updated state of the party (from OrgParty.States)
   */
  registerAttsAndFinalizeParty() {
    if (!User.isKeyPairSet()) {
      throw new Error("user should generate a key pair before linking to a conode");
    }
    if (!this.isPopDescComplete()) {
      throw new Error("organizer should complete the PopDesc first");
    }
    if (!this.isLinkedConodeSet()) {
      throw new Error("organizer should link to his conode first");
    }

    const descId = Uint8Array.from(this.getPopDescHash());
    if (descId.length === 0) {
      throw new Error("organizer should first register the config on his conode");
    }

    const attendees = this.getRegisteredAtts().slice();
    if (attendees.length === 0) {
      throw new Error("no attendee to register");
    }

    let hashToSign = HashJs.sha256();

    hashToSign.update(descId);
    attendees.forEach(attendee => {
      hashToSign.update(attendee);
    });

    hashToSign = Convert.hexToByteArray(hashToSign.digest("hex"));
    const privateKey = CURVE_ED25519_KYBER.scalar();
    privateKey.unmarshalBinary(User.getKeyPair().private);
    const signature = Schnorr.sign(CURVE_ED25519_KYBER, privateKey, hashToSign);


    const cothoritySocket = new Net.Socket(Convert.tlsToWebsocket(this.getLinkedConode(), ""), RequestPath.POP);
    const finalizeRequestMessage = CothorityMessages.createFinalizeRequest(descId, attendees, signature);

    return cothoritySocket.send(RequestPath.POP_FINALIZE_REQUEST, DecodeType.FINALIZE_RESPONSE, finalizeRequestMessage)
      .then(() => {
        this.setPopStatus(States.FINALIZED);
        return Promise.resolve(States.FINALIZED)
      })
      .catch(error => {
        if (error.message !== undefined && error.message.includes("Not all other conodes finalized yet")) {
          return Promise.resolve(States.FINALIZING);
        }
        console.log(error);
        console.dir(error);
        console.trace();

        return Promise.reject(error);
      });
  }

  /**
   * Load and reset functions and sub-functions to load/reset PoP.
   */

  /**
   * Completely resets the organizer.
   * @returns {Promise} - a promise that gets completed once the organizer has been reset
   */
  reset() {
    this._isLoaded = false;

    const promises = [this.setLinkedConode(EMPTY_SERVER_IDENTITY, true), this.setPopDesc(EMPTY_POP_DESC, true), this.setRegisteredAtts([], true)];

    return Promise.all(promises)
      .then(() => {
        return this.setPopDescHash(new Uint8Array(), true);
      })
      .then(() => {
        this._isLoaded = true;
        return Promise.resolve();
      })
      .catch(error => {
        console.log(error);
        console.dir(error);
        console.trace();

        return Promise.reject(error);
      });
  }

  /**
   * Main load function.
   * @returns {Promise} - a promise that gets resolved once everything belonging to OrgParty has been loaded into memory
   */
  load() {
    this._isLoaded = false;

    const promises = [
      this.loadLinkedConode(),
      this.loadPopDesc(),
      this.loadRegisteredAtts(),
      this.loadPopDescHash()
    ];

    return Promise.all(promises)
      .then(() => {
        return this.loadStatus();
      })
      .then(() => {
        this._isLoaded = true;
      })
      .catch(error => {
        console.log(error);
        console.dir(error);
        console.trace();

        return Promise.reject(error);
      });
  }

  /**
   * Loads the status of the current party from the linked conode
   * @returns {Promise} - a promise that gets resolved once the status is loaded
   */
  loadStatus() {
    const cothoritySocket = new Net.Socket(Convert.tlsToWebsocket(this.getLinkedConode(), ""), RequestPath.POP);
    const fetchRequest = CothorityMessages.createFetchRequest(this.getPopDescHash(), true);

    return cothoritySocket.send(RequestPath.POP_FETCH_REQUEST, DecodeType.FINALIZE_RESPONSE, fetchRequest)
      .then((response) => {
        if (Object.keys(response.final.attendees).length === 0) {
          this.setPopStatus(States.PUBLISHED);
        } else if (response.final.signature.length === 0) {
          this.setPopStatus(States.FINALIZING);
        } else {
          this.setPopStatus(States.FINALIZED);
          // We can add it to the user's final statements
          CothorityMessages.createFinalStatement(response.final.desc, response.final.attendees, response.final.signature, response.final.merged);
          return PoP.addFinalStatement(response.final, true)
        }

        return Promise.resolve();
      })
      .catch(error => {
        if (error.message !== undefined && error.message.includes("No config found")) {
          this.setPopStatus(States.CONFIGURATION);
        } else {
          this.setPopStatus(States.ERROR);
        }
        //Promise is resolved as the status is set to "error"
        return Promise.resolve(error);
      });

  }

  /**
   * Loads the linked conode into memory.
   * @returns {Promise} - a promise that gets resolved once the linked conode has been loaded into memory
   */
  loadLinkedConode() {
    return FileIO.getStringOf(FileIO.join(FilesPath.POP_ORG_PATH, this._dirname, FilesPath.POP_ORG_CONODE))
      .then(jsonLinkedConode => {
        if (jsonLinkedConode.length > 0) {
          const linkedConode = Convert.parseJsonServerIdentity(jsonLinkedConode);

          return this.setLinkedConode(linkedConode, false);
        } else {
          return Promise.resolve();
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
   * Loads the PopDesc into memory.
   * @returns {Promise} - a promise that gets resolved once the PopDesc has been loaded into memory
   */
  loadPopDesc() {
    return FileIO.getStringOf(FileIO.join(FilesPath.POP_ORG_PATH, this._dirname, FilesPath.POP_ORG_DESC))
      .then(jsonPopDesc => {
        if (jsonPopDesc.length > 0) {
          const popDesc = Convert.parseJsonPopDesc(jsonPopDesc);

          return this.setPopDesc(popDesc, false);
        } else {
          return Promise.resolve();
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
   * Loads the registered attendees into memory.
   * @returns {Promise} - a promise that gets resolved once all the registered attendees have been loaded into memory
   */
  loadRegisteredAtts() {
    return FileIO.getStringOf(FileIO.join(FilesPath.POP_ORG_PATH, this._dirname, FilesPath.POP_ORG_ATTENDEES))
      .then(jsonRegisteredAtts => {
        if (jsonRegisteredAtts.length > 0) {
          const registeredAtts = Convert.parseJsonArrayOfKeys(jsonRegisteredAtts);

          return this.setRegisteredAtts(registeredAtts, false);
        } else {
          return Promise.resolve();
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
   * Loads the PopDesc hash into memory.
   * @returns {Promise} - a promise that gets resolved once the PopDesc hash has been loaded into memory
   */
  loadPopDescHash() {
    return FileIO.getStringOf(FileIO.join(FilesPath.POP_ORG_PATH, this._dirname, FilesPath.POP_ORG_DESC_HASH))
      .then(jsonPopDescHash => {
        if (jsonPopDescHash.length > 0) {
          const popDescHash = Convert.parseJsonPopDescHash(jsonPopDescHash);

          return this.setPopDescHash(popDescHash, false);
        } else {
          return Promise.resolve();
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
   * Completely remove Party from disk
   * @returns {Promise} a promise that gets resolved once the party is deleted
   */
  remove() {
    return FileIO.removeFolder(FileIO.join(FilesPath.POP_ORG_PATH, this._dirname));
  }
}

/**
 * Enumerate the different possible state for a party
 * @readonly
 * @enum {string}
 */
const States = Object.freeze({
  /** Status is loading **/
  UNDEFINED: "loading",

  /** Party is still being configured (not published to the conode) **/
  CONFIGURATION: "configuration",

  /** Party is publishde (Stored) on the conode but not yet finalized **/
  PUBLISHED: "published",

  /** Party is fianlized **/
  FINALIZED: "finalized",

  /** Party is finalizing (not every nodes are finalized) **/
  FINALIZING: "finalizing",

  /** Used if the status connot be retrived **/
  ERROR: "offline"
});

// We export the class.
module.exports.Party = OrgParty;
module.exports.States = States;
