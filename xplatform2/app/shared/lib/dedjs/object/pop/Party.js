const CothorityMessages = require("../../network/cothority-messages");
const ObservableModule = require("data/observable");
const ObservableArray = require("data/observable-array").ObservableArray;


/**
 * We define the Party class which is the object representing the most basic form of a PoP Party.
 * More specific classes can be found in the respective folders of the organizer/attendee
 */
class Party {
    constructor() {
        this._popDesc = ObservableModule.fromObjectRecursive({
            name: "",
            datetime: "",
            location: "",
            roster: {
                id: new Uint8Array(),
                list: new ObservableArray(),
                aggregate: new Uint8Array()
            }
        });
    }


    /**
     * Returns the observable module for the pop description.
     * @returns {ObservableModule} - the observable module for the pop description
     */
    getPopDescModule() {
        return this._popDesc;
    }

    /**
     * Returns the pop description.
     * @returns {PopDesc} - the pop description
     */
    getPopDesc() {
        const popDescModule = this.getPopDescModule();

        let id = undefined;
        if (popDescModule.roster.id.length > 0) {
            id = popDescModule.roster.id;
        }

        const list = [];
        popDescModule.roster.list.forEach(server => {
            list.push(CothorityMessages.createServerIdentity(
                Uint8Array.from(server.public),
                Uint8Array.from(server.id),
                server.address,
                server.description));
        });

        const roster = CothorityMessages.createRoster(id, list, Uint8Array.from(popDescModule.roster.aggregate));

        return CothorityMessages.createPopDesc(popDescModule.name, popDescModule.datetime, popDescModule.location, roster);
    }

}

module.exports = Party;
