const ObservableModule = require("data/observable");
const ObservableArray = require("data/observable-array").ObservableArray;
const Package = require("../../Package");
const ObjectType = require("../../ObjectType");
const Helper = require("../../Helper");
const Convert = require("../../Convert");
const RequestPath = require("../../network/RequestPath");
const DecodeType = require("../../network/DecodeType");
const Net = require("@dedis/cothority").net;
const FilesPath = require("../../../../res/files/files-path");
const FileIO = require("../../../../lib/file-io/file-io");
const CothorityMessages = require("../../network/cothority-messages");
const RingSig = require("../../RingSig");
const Kyber = require("@dedis/kyber-js");
const Suite = new Kyber.curve.edwards25519.Curve;
const PopToken = require("./att/PopToken");

const User = require("../user/User").get;
const platform = require("tns-core-modules/platform");
var Directory = require("../../../Directory/Directory");
/**
 * This singleton is the PoP component of the app. It contains everything related to PoP in general and used by both, the organizer and the attendee.
 */

/**
 * We define the PoP class which is the object representing the PoP component of the app.
 */

class PoP {

  /**
   * Constructor for the PoP class.
   */
  constructor() {
    this._isLoaded = false;
    this._finalStatements = ObservableModule.fromObject({
      array: new ObservableArray()
    });
    this._popToken = ObservableModule.fromObject({
      array: new ObservableArray()
    });
  }

  /**
   * Getters and Setters.
   */

  /**
   * Gets the isLoaded property of PoP. It is only true once all the settings have been loaded into memory.
   * @returns {boolean} - a boolean that is true if PoP has completely been loaded into memory
   */
  isLoaded() {
    return this._isLoaded;
  }

  /**
   * Gets the final statements array.
   * @returns {ObservableArray} - an observable array containing all the final statements
   */
  getFinalStatements() {
    return this.getFinalStatementsModule().array;
  }

  /**
   * Gets the final statements module.
   * @returns {ObservableModule} - an observable module/object containing everything related to the final statements (including the array of final statements)
   */
  getFinalStatementsModule() {
    return this._finalStatements;
  }

  /**
   * Gets the PoP-Token array.
   * @returns {ObservableArray} - an observable array containing all the PoP-Token
   */
  getPopToken() {
    return this.getPopTokenModule().array;
  }

  /**
   * Gets the PoP-Token module.
   * @returns {ObservableModule} - an observable module/object containing everything related to the PoP-Token (including the array of PoP-Token)
   */
  getPopTokenModule() {
    return this._popToken;
  }

  /**
   * Sets the new final statements array given as parameter.
   * @param {Array} array - the new final statements to set
   * @param {boolean} save - if the new final statements array should be saved permanently
   * @returns {Promise} - a promise that gets resolved once the new final statements array has been set and saved if the save parameter is set to true
   */
  setFinalStatementsArray(array, save) {
    if (!(array instanceof Array)) {
      throw new Error("array must be an instance of Array");
    }
    if (array.length === 0 || !Helper.isOfType(array[0], ObjectType.FINAL_STATEMENT)) {
      throw new Error("array is empty or array[i] is not instance of FinalStatement");
    }
    if (typeof save !== "boolean") {
      throw new Error("save must be of type boolean");
    }

    this.emptyFinalStatementArray()

    if (array.length === 1) {
      return this.addFinalStatement(array[0], save);
    } else {
      const promises = [];
      for (let i = 0; i < array.length - 1; ++i) {
        promises.push(this.addFinalStatement(array[i], false));
      }

      return Promise.all(promises)
        .then(() => {
          return this.addFinalStatement(array[array.length - 1], save);
        });
    }
  }

  /**
   * Sets the new PoP-Token array given as parameter.
   * @param {Array} array - the new PoP-Token array to set
   * @param {boolean} save - if the new PoP-Token array should be saved permanently
   * @returns {Promise} - a promise that gets resolved once the new PoP-Token array has been set and saved if the save parameter is set to true
   */
  setPopTokenArray(array, save) {
    if (!(array instanceof Array)) {
      throw new Error("array must be an instance of Array");
    }
    if (array.length === 0 || !Helper.isOfType(array[0], ObjectType.POP_TOKEN)) {
      throw new Error("array is empty or array[i] is not an instance of PopToken");
    }
    if (typeof save !== "boolean") {
      throw new Error("save must be of type boolean");
    }

    this.emptyPopTokenArray();

    if (array.length === 1) {
      return this.addPopToken(array[0], save);
    } else {
      const promises = [];
      for (let i = 0; i < array.length - 1; ++i) {
        promises.push(this.addPopToken(array[i], false));
      }

      return Promise.all(promises)
        .then(() => {
          return this.addPopToken(array[array.length - 1], save);
        });
    }
  }

  /**
   * Action functions.
   */

  /**
   * Empties the final statements array (this action is not saved permanently).
   */
  emptyFinalStatementArray() {
    while (this.getFinalStatements().length > 0) {
      this.getFinalStatements().pop();
    }
  }

  /**
   * Empties the PoP-Token array (this action is not saved permanently).
   */
  emptyPopTokenArray() {
    while (this.getPopToken().length > 0) {
      this.getPopToken().pop();
    }
  }

  /**
   * Adds the new final statement given as parameter to the list of final statements.
   * @param {FinalStatement} finalStatement - the new final statement to add
   * @param {boolean} save - if the new final statement should be saved permanently
   * @returns {Promise} - a promise that gets resolved once the new final statement has been added and saved if the save parameter is set to true
   */
  addFinalStatement(finalStatement, save) {
    if (!Helper.isOfType(finalStatement, ObjectType.FINAL_STATEMENT)) {
      throw new Error("finalStatement must be an instance of FinalStatement");
    }
    if (typeof save !== "boolean") {
      throw new Error("save must be of type boolean");
    }
    let alreadyExists = false;
    const oldFinalStatements = this.getFinalStatements().slice();
    oldFinalStatements.forEach(statement => {
      if (Convert.byteArrayToHex(statement.signature) === Convert.byteArrayToHex(finalStatement.signature)) {
        alreadyExists = true;
      }
    });

    if (alreadyExists) {
      return Promise.resolve();
    }

    this.getFinalStatements().push(finalStatement);

    const newFinalStatements = this.getFinalStatements().slice();

    if (save) {
      let toWrite = "";
      if (newFinalStatements.length > 0) {
        const object = {};
        object.array = newFinalStatements;

        toWrite = Convert.objectToJson(object);
      }


          return FileIO.writeStringTo(FilesPath.POP_FINAL_STATEMENTS, toWrite)
              .catch((error) => {
              console.log(error);
          console.dir(error);
          console.trace();

          return this.setFinalStatementsArray(oldFinalStatements, false)
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
   * Adds the new PoP-Token given as parameter to the list of PoP-Token.
   * @param {PopToken} popToken - the new PoP-Token to add
   * @param {boolean} save - if the new PoPToken should be saved permanently
   * @returns {Promise} - a promise that gets resolved once the new PoP-Token has been added and saved if the save parameter is set to true
   */
  addPopToken(popToken, save) {
    if (!Helper.isOfType(popToken, ObjectType.POP_TOKEN)) {
      throw new Error("popToken must be an instance of PopToken");
    }
    if (typeof save !== "boolean") {
      throw new Error("save must be of type boolean");
    }

    const oldPopToken = this.getPopToken().slice();

    popToken.toHex = Convert.byteArrayToHex;
    this.getPopToken().push(popToken);

    const newPopToken = this.getPopToken().slice();

    if (save) {
      let toWrite = "";
      if (newPopToken.length > 0) {
        const object = {};
        object.array = newPopToken;

        toWrite = Convert.objectToJson(object);
      }


         return FileIO.writeStringTo(FilesPath.POP_TOKEN, toWrite)
             .catch((error) => {
             console.log(error);
         console.dir(error);
         console.trace();

         return this.setPopTokenArray(oldPopToken, false)
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

  addPopTokenFromFinalStatement(finalStatement, keyPair, save, party) {
      if (!Helper.isOfType(finalStatement, ObjectType.FINAL_STATEMENT)) {
          throw new Error("finalStatement must be an instance of FinalStatement");
      }
      if (typeof save !== "boolean") {
          throw new Error("save must be of type boolean");
      }
      if (!Helper.isOfType(keyPair, ObjectType.KEY_PAIR)) {
          throw new Error("keyPair must be an instance of KeyPair");
      }

      const popToken = new PopToken(finalStatement, keyPair.private, keyPair.public);
      party.setPopToken(popToken);
      return this.addPopToken(popToken, save);
  }

  /**
   * Removes the final statement corresponding to the index given as parameter.
   * @param {number} index - the index of the final statement to remove
   * @returns {Promise} - a promise that gets resolved once the final statement has been removed permanently
   */
  deleteFinalStatementByIndex(index) {
    if (typeof index !== "number") {
      throw new Error("index must be of type number");
    }
    if (!(0 <= index && index < this.getFinalStatements().length)) {
      throw new Error("index is not in the range of the final statements list");
    }

    const newArray = [];
    for (let i = 0; i < this.getFinalStatements().length; ++i) {
      if (i !== index) {
        newArray.push(this.getFinalStatements().getItem(i));
      }
    }

    if (newArray.length > 0) {
      return this.setFinalStatementsArray(newArray, true);
    } else {

          return FileIO.writeStringTo(FilesPath.POP_FINAL_STATEMENTS, "")
              .then(() => {
              this.emptyFinalStatementArray();

          return Promise.resolve();
      });

    }
  }

  /**
   * Revokes the PoP-Token corresponding to the index given as parameter.
   * This action will delete the PoP-Token permanently and re-add the final statement to the list of final statements.
   * @param {number} index - the index of the PoP-Token to revoke
   * @returns {Promise} - a promise that gets resolved once the PoP-Token has been revoked permanently
   */
  revokePopTokenByIndex(index) {
    if (typeof index !== "number") {
      throw new Error("index must be of type number");
    }
    if (!(0 <= index && index < this.getPopToken().length)) {
      throw new Error("index is not in the range of the PoP-Token list");
    }

    const finalStatement = this.getPopToken().getItem(index).final;
    const newArray = [];
    for (let i = 0; i < this.getPopToken().length; ++i) {
      if (i !== index) {
        newArray.push(this.getPopToken().getItem(i));
      }
    }

    if (newArray.length > 0) {
      return this.addFinalStatement(finalStatement, true)
        .then(() => {
          return this.setPopTokenArray(newArray, true);
        });
    } else {
      return this.addFinalStatement(finalStatement, true)
        .then(() => {


            return FileIO.writeStringTo(FilesPath.POP_TOKEN, "");


        })
        .then(() => {
          this.emptyPopTokenArray();

          return Promise.resolve();
        });
    }
  }

  /**
   * Generates a new PoP-Token using the User's key pair and the final statement corresponding to the index given as parameter.
   * This action will "consume" the final statement.
   * @param {number} index - the index of the final statement to use
   * @returns {Promise} - a promise that gets resolved once the PoP-Token has been generated and saved permanently
   */
  generatePopTokenByIndex(index) {
    if (!User.isKeyPairSet()) {
      throw new Error("user should have a key pair before generating a pop token");
    }
    if (typeof index !== "number") {
      throw new Error("index must be of type number");
    }
    if (!(0 <= index && index < this.getFinalStatements().length)) {
      throw new Error("index is not in the range of the final statements list");
    }

    return this.addPopTokenFromFinalStatement(this.getFinalStatements().getItem(index), User.getKeyPair(), true)
      .then(() => {
        return this.deleteFinalStatementByIndex(index);
      });
  }

  /**
   * Fetches the FinalStatement corresponding to the description id given as parameter.
   * @param {ServerIdentity} conode - the conode from which to fetch the final statement
   * @param {Uint8Array} descId - the id of the PopDesc
   * @returns {Promise} - a promise that gets completed once the final statement has been fetched and saved locally
   */
  fetchFinalStatement(conode, descId) {
    if (!Helper.isOfType(conode, ObjectType.SERVER_IDENTITY)) {
      throw new Error("conode must be an instance of ServerIdentity");
    }
    if (!(descId instanceof Uint8Array) || descId.length === 0) {
      throw new Error("descId must be an instance of Uint8Array and not empty");
    }

    const cothoritySocket = new Net.Socket(Convert.tlsToWebsocket(conode, ""), RequestPath.POP);
    const fetchRequestMessage = CothorityMessages.createFetchRequest(descId);

    return cothoritySocket.send(RequestPath.POP_FETCH_REQUEST, DecodeType.FETCH_RESPONSE, fetchRequestMessage)
      .then(response => {
        return this.addFinalStatement(response.final, true);
      })
      .catch(error => {
        console.log(error);
        console.dir(error);
        console.trace();

        return Promise.reject(error);
      });
  }

  /**
   * Sign a message using (un)linkable ring signature
   *
   * @param {Integer} index - the index of the pop token used to sign the message
   * @param {Uint8Array} message -  the message to be signed
   * @param {Uint8Array} [scope] - has to be given if linkable ring signature is used
   * @return {Uint8Array} - the signature
   */
  signWithPopTokenIndex(index, message, scope) {
    if (!Number.isInteger(index) || index < 0 || index >= this.getPopToken().length) {
      throw "index is not valid"
    }
    if (!message instanceof Uint8Array) {
      throw "message should be an Uint8Array"
    }
    if (!scope instanceof Uint8Array) {
      throw "scope should be an Uint8Array"
    }
    let popToken = this.getPopToken().getItem(index);
    let attendees = popToken.final.attendees;
    let anonimitySet = new Set();
    let minePublic = Suite.point();
    minePublic.unmarshalBinary(popToken.public);
    let minePrivate = Suite.scalar();
    minePrivate.unmarshalBinary(popToken.private);
    let mine = -1;
    for (let i = 0; i < attendees.length; i++) {
      let attendee = attendees[i];

      let point = Suite.point();
      point.unmarshalBinary(attendee);
      anonimitySet.add(point);
      if (point.equal(minePublic)) {
        mine = i;
      }
    }

    if (mine < 0) {
      throw "Pop Token is invalid"
    }

    return RingSig.Sign(Suite, message, [...anonimitySet], scope, mine, minePrivate)
  }


    /**
     * Sign a message using (un)linkable ring signature
     *
     * @param PopToken Instance - the  pop token used to sign the message
     * @param {Uint8Array} message -  the message to be signed
     * @param {Uint8Array} [scope] - has to be given if linkable ring signature is used
     * @return {Uint8Array} - the signature
     */
    signWithPopToken(popToken, message, scope) {


        let attendees = popToken.final.attendees;
        let anonimitySet = new Set();
        let minePublic = Suite.point();
        minePublic.unmarshalBinary(popToken.public);
        let minePrivate = Suite.scalar();
        minePrivate.unmarshalBinary(popToken.private);
        let mine = -1;
        for (let i = 0; i < attendees.length; i++) {
            let attendee = attendees[i];

            let point = Suite.point();
            point.unmarshalBinary(attendee);
            anonimitySet.add(point);
            if (point.equal(minePublic)) {
                mine = i;
            }
        }

        if (mine < 0) {
            throw "Pop Token is invalid"
        }

        return RingSig.Sign(Suite, message, [...anonimitySet], scope, mine, minePrivate)
    }

    /**
   * Load and reset functions and sub-functions to load/reset PoP.
   */

  /**
   * Completely resets PoP.
   * @returns {Promise} - a promise that gets completed once PoP has been reset
   */
  reset() {
    this._isLoaded = false;


        const promises = [FileIO.writeStringTo(FilesPath.POP_FINAL_STATEMENTS, ""), FileIO.writeStringTo(FilesPath.POP_TOKEN, "")];

        return Promise.all(promises)
            .then(() => {
            this.emptyFinalStatementArray();
        this.emptyPopTokenArray();

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
   * @returns {Promise} - a promise that gets resolved once everything belonging to PoP has been loaded into memory
   */
  load() {
    this._isLoaded = false;

    const promises = [this.loadFinalStatements(), this.loadPopToken()];

    return Promise.all(promises)
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
   * Loads all the final statements into memory.
   * @returns {Promise} - a promise that gets resolved once all the final statements have been loaded into memory
   */
  loadFinalStatements() {

        return FileIO.getStringOf(FilesPath.POP_FINAL_STATEMENTS)
            .then(jsonFinalStatements => {
            if (jsonFinalStatements.length > 0) {
            const finalStatementsArray = Convert.parseJsonFinalStatementsArray(jsonFinalStatements);

            return this.setFinalStatementsArray(finalStatementsArray, false);
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
   * Loads all the PoP-Token into memory.
   * @returns {Promise} - a promise that gets resolved once all the PoP-Token have been loaded into memory
   */
  loadPopToken() {

        return FileIO.getStringOf(FilesPath.POP_TOKEN)
            .then(jsonPopToken => {
            if (jsonPopToken.length > 0) {
            const popTokenArray = Convert.parseJsonPopTokenArray(jsonPopToken);

            return this.setPopTokenArray(popTokenArray, false);
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
}

/**
 * Now we create a singleton object for PoP.
 */

// The symbol key reference that the singleton will use.
const POP_PACKAGE_KEY = Symbol.for(Package.POP);

// We create the singleton if it hasn't been instanciated yet.
const globalSymbols = Object.getOwnPropertySymbols(global);
const popExists = (globalSymbols.indexOf(POP_PACKAGE_KEY) >= 0);

if (!popExists) {
  global[POP_PACKAGE_KEY] = (function () {
    const newPoP = new PoP();
    newPoP.load();

    return newPoP;
  })();
}

// Singleton API
const POP = {};

Object.defineProperty(POP, "get", {
  configurable: false,
  enumerable: false,
  get: function () {
    return global[POP_PACKAGE_KEY];
  },
  set: undefined
});

// We freeze the singleton.
Object.freeze(POP);

// We export only the singleton API.
module.exports = POP;
