const Convert = require("../../../lib/dedjs/Convert");
const NetDedis = require("@dedis/cothority").net;
const RequestPath = require("../../../lib/dedjs/network/RequestPath");
const DecodeType = require("../../../lib/dedjs/network/DecodeType");
const StatusExtractor = require("../../../lib/dedjs/extractor/StatusExtractor");
const CothorityMessages = require("../../../lib/dedjs/network/cothority-messages");
const Helper = require("../../../lib/dedjs/Helper");

function getServerIdentiyFromAddress(address) {
    if (!Helper.isValidAddress(address)) {
        return Promise.reject("Invalid address.")
    }

    const statusRequestMessage = CothorityMessages.createStatusRequest();
    const cothoritySocket = new NetDedis.Socket(Convert.tlsToWebsocket(address, ""), RequestPath.STATUS);

    return cothoritySocket.send(RequestPath.STATUS_REQUEST, DecodeType.STATUS_RESPONSE, statusRequestMessage)
        .then(statusResponse => {
            const hexKey = StatusExtractor.getPublicKey(statusResponse);
            const description = StatusExtractor.getDescription(statusResponse);
            const id = StatusExtractor.getID(statusResponse);
            const server = Convert.toServerIdentity(address, Convert.hexToByteArray(hexKey), description, Convert.hexToByteArray(id));

            return Promise.resolve(server);
        })

}

module.exports.getServerIdentiyFromAddress = getServerIdentiyFromAddress;
