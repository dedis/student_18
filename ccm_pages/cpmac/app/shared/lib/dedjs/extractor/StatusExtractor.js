const Convert = require("../Convert");
const ObjectType = require("../ObjectType");
const Helper = require("../Helper");

/**
 * @file Library to extract stats from a status response.
 * @param {Response} statusResponse - a status response from a conode
 * @returns {string} - the wanted stat of the conode
 */

function throwErrorIfTypeIsWrong(statusResponse) {
  if (!Helper.isOfType(statusResponse, ObjectType.STATUS_RESPONSE)) {
    throw new Error("statusResponse must be of type Response");
  }
}

function getDescription(statusResponse) {
  throwErrorIfTypeIsWrong(statusResponse)
  return statusResponse.server.description;
}

function getAddress(statusResponse) {
  throwErrorIfTypeIsWrong(statusResponse)
  return statusResponse.server.address;
}

function getID(statusResponse) {
  throwErrorIfTypeIsWrong(statusResponse)
  return Convert.byteArrayToHex(statusResponse.server.id);
}

function getPublicKey(statusResponse) {
  throwErrorIfTypeIsWrong(statusResponse)
  return Convert.byteArrayToHex(statusResponse.server.public);
}

function getServices(statusResponse) {
  throwErrorIfTypeIsWrong(statusResponse)
  return statusResponse.system.Generic.field.Available_Services;
}

function getSystem(statusResponse) {
  throwErrorIfTypeIsWrong(statusResponse)
  return statusResponse.system.Generic.field.System;
}

function getHost(statusResponse) {
  throwErrorIfTypeIsWrong(statusResponse)
  return statusResponse.system.Generic.field.Host;
}

function getPort(statusResponse) {
  throwErrorIfTypeIsWrong(statusResponse)
  return statusResponse.system.Generic.field.Port;
}

function getConnectionType(statusResponse) {
  throwErrorIfTypeIsWrong(statusResponse)
  return statusResponse.system.Generic.field.ConnType;
}

function getVersion(statusResponse) {
  throwErrorIfTypeIsWrong(statusResponse)
  return statusResponse.system.Generic.field.Version;
}

function getTXBytes(statusResponse) {
  throwErrorIfTypeIsWrong(statusResponse)
  return statusResponse.system.Generic.field.TX_bytes;
}

function getRXBytes(statusResponse) {
  throwErrorIfTypeIsWrong(statusResponse)
  return statusResponse.system.Generic.field.RX_bytes;
}

function getUptime(statusResponse) {
  throwErrorIfTypeIsWrong(statusResponse)
  return statusResponse.system.Generic.field.Uptime;
}

module.exports.getDescription = getDescription;
module.exports.getAddress = getAddress;
module.exports.getID = getID;
module.exports.getPublicKey = getPublicKey;
module.exports.getServices = getServices;
module.exports.getSystem = getSystem;
module.exports.getHost = getHost;
module.exports.getPort = getPort;
module.exports.getConnectionType = getConnectionType;
module.exports.getVersion = getVersion;
module.exports.getTXBytes = getTXBytes;
module.exports.getRXBytes = getRXBytes;
module.exports.getUptime = getUptime;
