/**
 * @file File containing the paths for files used to store information permanently.
 */

/**
 * General settings files.
 */
const ROSTER = "shared/res/files/user/roster.json";
const USER_NAME = "shared/res/files/user/name.json";
const KEY_PAIR = "keypair.json";


/**
 * PoP Files
 */
const POP_FINAL_STATEMENTS = "shared/res/files/pop/final_statements.json";
const POP_TOKEN = "shared/res/files/pop/token.json";


const POP_ORG_DESC = "description.json";
const POP_ORG_DESC_HASH = "hash.json";
const POP_ORG_ATTENDEES = "attendees.json";

const POP_ATT_PATH = "shared/res/files/pop/att";
const POP_ATT_FINAL = "final_statements.json";
const POP_ATT_INFOS = "party_informations.json";

/**
 * CISC Files
 */
const CISC_PATH = "shared/res/files/cisc";
const CISC_IDENTITY_LINK = "identity_link.json";
const CISC_NAME = "name.json";

/**
 * USER files
 */
const USER_PATH = "shared/res/files/user";
const POP_ORG_PATH = "shared/res/files/pop/org";
const POP_ORG_CONODE = "conode.json";
/**
 * BEERCOIN Files
 */
const BEERCOIN_PATH = "shared/res/files/beercoin";
const BEERCOIN_BAR_CONFIG = "bar_config.json";
const BEERCOIN_LINKED_FINALS = POP_ATT_FINAL;
const BEERCOIN_CHECKED_CLIENTS = "checked_clients.json";
const BEERCOIN_ORDER_HISTORY = "order_history.json";

module.exports.ROSTER = ROSTER;
module.exports.USER_NAME = USER_NAME;
module.exports.KEY_PAIR = KEY_PAIR;
module.exports.POP_FINAL_STATEMENTS = POP_FINAL_STATEMENTS;
module.exports.POP_TOKEN = POP_TOKEN;
module.exports.POP_ORG_PATH = POP_ORG_PATH;
module.exports.POP_ORG_CONODE = POP_ORG_CONODE;
module.exports.POP_ORG_DESC = POP_ORG_DESC;
module.exports.POP_ORG_DESC_HASH = POP_ORG_DESC_HASH;
module.exports.POP_ORG_ATTENDEES = POP_ORG_ATTENDEES;
module.exports.CISC_IDENTITY_LINK = CISC_IDENTITY_LINK;
module.exports.CISC_NAME = CISC_NAME;
module.exports.USER_PATH = USER_PATH;
module.exports.POP_ATT_PATH = POP_ATT_PATH;
module.exports.POP_ATT_FINAL = POP_ATT_FINAL;
module.exports.CISC_PATH = CISC_PATH;
module.exports.BEERCOIN_PATH = BEERCOIN_PATH;
module.exports.BEERCOIN_BAR_CONFIG = BEERCOIN_BAR_CONFIG;
module.exports.BEERCOIN_LINKED_FINALS = BEERCOIN_LINKED_FINALS;
module.exports.BEERCOIN_CHECKED_CLIENTS = BEERCOIN_CHECKED_CLIENTS;
module.exports.BEERCOIN_ORDER_HISTORY = BEERCOIN_ORDER_HISTORY;
module.exports.POP_ATT_INFOS = POP_ATT_INFOS;