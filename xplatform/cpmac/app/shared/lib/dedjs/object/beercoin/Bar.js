const uuidv4 = require("uuid/v4");
const Helper = require("../../Helper");
const ObjectType = require("../../ObjectType");
const FileIO = require("../../../file-io/file-io");
const FilesPath = require("../../../../res/files/files-path");
const Convert = require("../../Convert");
const ObservableArray = require("data/observable-array").ObservableArray;
const Observable = require("data/observable");
const RingSig = require("../../RingSig");
const Kyber = require("@dedis/kyber-js");
const Suite = new Kyber.curve.edwards25519.Curve;
const Crypto = require("crypto-browserify");

/**
 * @param {string} [dirname] - directory of the bar data (directory is created if non existent).
 *  If no directory is specified, a unique random directory name is generated
 **/
class Bar {

  constructor(dirname) {
    if (typeof dirname !== "string") {
      throw new Error("dirname should be of type string or undefined");
    }
    this._dirname = dirname;
    this._config = Observable.fromObject({
      name: "",
      frequency: "",
      date: new Date(Date.now())
    });
    this._checkedClients = [];
    this._finalStatement = undefined;
    this._anonymitySet = new Set();
    this._orderHistory = new ObservableArray();

    this.load()
  }

  /**
   * Add a new date to the order history
   *
   * @param date - the date that will be added
   * @return {Promise} - a promise that gets resolved once the new history is saved on the disk
   */
  addOrderToHistory(date) {
    if(!(date instanceof Date)) {
      throw "date must be an instance of Date"
    }

    const history = this.getOrderHistoryModule();
    history.push(date.toString());

    return this.saveHistory()
  }

  /**
   * Load everything that is related to this bar in memory :
   *  - The already check clients
   *  - The linked final statements
   *  - The configuration
   * @return {Promise<[any]>}
   */
  load() {
    const promises = [this.loadConfig(), this.loadFinalStatements(), this.loadOrderHistory()];

    return Promise.all(promises)
      .then(() => {
        // needs to be done after, as the period may need to be reset (thus we check the config before)
        return this.loadCheckedClients();
      })
      .catch(error => {
        console.log(error);
        console.dir(error);
        console.trace();

        return Promise.reject(error)
      })
  }

  /**
   * Load the configuration in memory
   * @return {Promise<void>} - a promise that gets resolved once the configuration is loaded
   */
  loadConfig() {
    return FileIO.getStringOf(FileIO.join(FilesPath.BEERCOIN_PATH, this._dirname, FilesPath.BEERCOIN_BAR_CONFIG))
      .then(configJson => {
        const config = Convert.jsonToObject(configJson);
        const configModule = this.getConfigModule();
        const ONE_DAY = 24 * 60 * 60 * 1000;

        configModule.name = config.name;
        configModule.frequency = config.frequency;
        configModule.date = new Date(+config.date); // + permforms the conversion to Int


        console.log("SKDEBUG");
        console.log("val 1 = " + Date.now());
        console.log("valval 2 = " + configModule.date);
        console.log("json = " + configJson);
        console.dir(config);

        let numberOfDay = Math.floor((Date.now() - configModule.date.getTime()) / ONE_DAY);
        let maxDays;

        switch (configModule.frequency) {
          case Frequencies.DAILY:
            maxDays = 1;
            break;
          case Frequencies.WEEKLY:
            maxDays = 7;
            break;
          case Frequencies.MONTHLY:
            maxDays = 30;
            break;
          default:
            throw "Date is not valid"
        }


        console.log("nb of day =" + numberOfDay);
        console.log("max days ="  + maxDays);

        if (numberOfDay >= maxDays) {
          return this.resetPeriod()
        }


        return Promise.resolve();
      })
  }

  /**
   * Load the already checked clients in memory
   * @return {Promise<void>} - a promise that gets resolved once the clients are loaded
   */
  loadCheckedClients() {
    return FileIO.getStringOf(FileIO.join(FilesPath.BEERCOIN_PATH, this._dirname, FilesPath.BEERCOIN_CHECKED_CLIENTS))
      .then(checkedClientsJson => {
        if (checkedClientsJson.length === 0) {
          return Promise.resolve();
        }
        const checkedClients = Convert.jsonToObject(checkedClientsJson);
        const checkedClientsModule = this.getCheckedClientsModule();

        checkedClients.clients.forEach(client => {
          checkedClientsModule.push(client)
        });

        return Promise.resolve();
      })

  }

  /**
   * Load the final statements in memory
   * @return {Promise<void>} - a promise that gets resolved once the final statements are loaded
   */
  loadFinalStatements() {
    return FileIO.getStringOf(FileIO.join(FilesPath.BEERCOIN_PATH, this._dirname, FilesPath.BEERCOIN_LINKED_FINALS))
      .then(finalStatementJson => {

        this._finalStatement = Convert.jsonToObject(finalStatementJson);

        this._finalStatement.attendees.forEach(attendee => {
          let publicKey = Suite.point();
          publicKey.unmarshalBinary(Convert.base64ToByteArray(attendee));
          this._anonymitySet.add(publicKey)
        });

        return Promise.resolve();
      })
  }

  /**
   * Load the order history in memory
   * @return {Promise} - a promise that gets resolved once the history is loaded
   */
  loadOrderHistory() {
    return FileIO.getStringOf(FileIO.join(FilesPath.BEERCOIN_PATH, this._dirname, FilesPath.BEERCOIN_ORDER_HISTORY))
      .then(orderHistoryJson => {
        if (orderHistoryJson.length === 0) {
          return Promise.resolve()
        }

        const orderHistory = Convert.jsonToObject(orderHistoryJson);
        const orderHistoryModule = this.getOrderHistoryModule();
        orderHistory.dates.forEach(date => {
          orderHistoryModule.push(new Date(date))
        })
      })
  }

  /**
   * Save the list of checked client of this
   * @return {Promise} - a promise that gets solved once the it is saved
   */
  saveCheckedClients() {
    let clients = [];
    this.getCheckedClientsModule().forEach(client => {
      clients.push(client);
    });

    const fields = {
      clients: clients
    };

    const objectString = Convert.objectToJson(fields);

    return FileIO.writeStringTo(FileIO.join(FilesPath.BEERCOIN_PATH, this._dirname, FilesPath.BEERCOIN_CHECKED_CLIENTS), objectString)
      .catch(error => {
        console.log(error);
        console.dir(error);
        console.trace();

        return Promise.reject(error)
      })
  }

  /**
   * Save the current bar configuration on the disk
   *
   * @return {Promise} - a promise that gets solved once the config is saved on the disk
   */
  saveConfig() {
    let currentConfig = this.getConfigModule();

    const config = {
      name: currentConfig.name,
      frequency: currentConfig.frequency,
      date: currentConfig.date.toString(),
    };

    const configString = Convert.objectToJson(config);

    return FileIO.writeStringTo(FileIO.join(FilesPath.BEERCOIN_PATH, this._dirname, FilesPath.BEERCOIN_BAR_CONFIG), configString)
  }

  /**
   * Save the current history on the disk
   * @return {Promise} - a promise that gets solved once the datas are on the disk
   */
  saveHistory() {
    let dates = [];
    let history = this.getOrderHistoryModule();

    history.forEach(date => {
      dates.push(date.toString())
    });

    const fields = {
      dates: dates
    };

    let historyString = Convert.objectToJson(fields);

    return FileIO.writeStringTo(FileIO.join(FilesPath.BEERCOIN_PATH, this._dirname, FilesPath.BEERCOIN_ORDER_HISTORY), historyString)

  }

  /**
   * Check if a specific tag has already been registered to this bar
   *
   * @param tag - the tag to be checked
   * @return {boolean} - true if this client already came here
   */
  isAlreadyChecked(tag) {
    if (!(tag instanceof Uint8Array)) {
      throw "tag must be an Uint8Array";
    }

    const hexString = Convert.byteArrayToHex(tag);
    return this.getCheckedClientsModule().indexOf(hexString) >= 0;
  }

  /**
   * Reset the current period (set to date to now and clear the list of checked clients)
   *
   * @return {Promise} - a promise that gets solved when everything (config + check clients) is saved to disk
   */
  resetPeriod() {
    const configModule = this.getConfigModule();
    configModule.date = new Date(Date.now());

    const checkedClients = this.getCheckedClientsModule();
    checkedClients.splice(0);

    const promises = [this.saveCheckedClients(), this.saveConfig()];

    return Promise.all(promises)
      .catch(error => {
        console.log(error);
        console.dir(error);
        console.trace();

        return Promise.reject()
      })
  }

  /**
   * Empty the history and save it on the disk
   * @return {Promise} - a promise that gets solved once the history is cleared in memory and on the disk
   */
  resetOrderHistory() {
    const history = this.getOrderHistoryModule();
    history.splice(0);

    return this.saveHistory();
  }

  /**
   * Register a new client and save it on the disk
   *
   * @param signature - the new client signature
   * @param signingData - the signing info used to register a client. Shoul be an object oh hex string
   * @return {Promise} - a promise that gets solved once the save process is finished if the client is not already
   * registered
   */
  registerClient(signature, signingData) {
    if (!(signature instanceof Uint8Array)) {
      throw "signature must be an Uint8Array";
    }


    let nonce = Convert.hexToByteArray(signingData.nonce);
    let scope = Convert.hexToByteArray(signingData.scope);


    const verifInfo = RingSig.Verify(Suite, nonce, [...this._anonymitySet], scope, signature);
    if (!verifInfo.valid) {
      return Promise.reject("You are not part of the right group !")
    } else if (this.isAlreadyChecked(verifInfo.tag)) {
      return Promise.reject("You already had a beer ! Please come back later")
    }

    const hexString = Convert.byteArrayToHex(verifInfo.tag);
    this.getCheckedClientsModule().push(hexString);

    return this.saveCheckedClients();
  }


  /**
   * Get the datas used that will be signed to identificate an user
   *
   * @return {{nonce: Uint8Array, scope: Uint8Array}}
   */
  getSigningData() {
    const configModule = this.getConfigModule();

    const nonce = Crypto.randomBytes(16);
    const scopeString =
      configModule.name +
      configModule.frequency +
      configModule.date.getFullYear() +
      configModule.date.getMonth() +
      configModule.date.getDay();
    const scope = new Uint8Array(Buffer.from(scopeString));

    return {
      nonce: Convert.byteArrayToHex(nonce),
      scope: Convert.byteArrayToHex(scope)
    }
  }

  /**
   * Return the history of the ordered beer since the last reset
   *
   * @return {ObservableArray}
   */
  getOrderHistoryModule() {
    return this._orderHistory;
  }

  /**
   * @return {Observable} - the observable config module
   */
  getConfigModule() {
    return this._config;
  }

  /**
   * @return {ObservableArray} - the observable array of the checked clients
   */
  getCheckedClientsModule() {
    return this._checkedClients;
  }

  /**
   * @return {ObservableArray} - the observable array of the final statements
   */
  getFinalStatement() {
    return this._finalStatement;
  }

  /**
   * Create a new bar and save it locally
   *
   * @param {String} name - the name of the bar
   * @param {String} frequency - the frequency at which clients can have a beer. Should be a member of Frequencies enum
   * @param {FinalStatement} finalStatement - the linked final statement to get the allowed clients
   * @return {Promise<Bar>} - a promise that gets solved when the bar is correctly saved on the disk
   */
  static createWithConfig(name, frequency, finalStatement) {
    if (typeof name !== "string") {
      throw new Error("name must be of type string");
    }

    if (!Object.values(Frequencies).includes(frequency)) {
      throw new Error("frequency must be part of the Frequencies enumeration");
    }

    if (!Helper.isOfType(finalStatement, ObjectType.FINAL_STATEMENT)) {
      throw new Error("finalStatement must be of type FinalStatement");
    }

    const config = {
      name: name,
      frequency: frequency,
      date: Date.now().toString(),
    };

    const configString = Convert.objectToJson(config);
    const finalStatementString = Convert.objectToJson(finalStatement);
    const dirname = uuidv4();

    return FileIO.writeStringTo(FileIO.join(FilesPath.BEERCOIN_PATH, dirname, FilesPath.BEERCOIN_LINKED_FINALS), finalStatementString)
      .then(() => {
        return FileIO.writeStringTo(FileIO.join(FilesPath.BEERCOIN_PATH, dirname, FilesPath.BEERCOIN_BAR_CONFIG), configString)
      })
      .then(() => {
        return Promise.resolve(new Bar(dirname));
      })
      .catch(error => {
        console.log(error);
        console.dir(error);
        console.trace();
        FileIO.removeFolder(FileIO.join(FilesPath.BEERCOIN_PATH, dirname));

        return Promise.reject(error)
      })

  }

  /**
   * Completely remove the Bar from disk
   * @returns {Promise} a promise that gets resolved once the bar is deleted
   */
  remove() {
    return FileIO.removeFolder(FileIO.join(FilesPath.BEERCOIN_PATH, this._dirname));
  }

}

/**
 * Enumerate the different possible frequency for a bar
 * @readonly
 * @enum {string}
 */
const Frequencies = Object.freeze({
  DAILY: "daily",

  WEEKLY: "weekly",

  MONTHLY: "monthly",
});

module.exports.Bar = Bar;
module.exports.Frequencies = Frequencies;
