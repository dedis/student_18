/**
 * @file File containing different available paths for the Cothority.
 */
/**
 * Services
 */
const STATUS = "Status";
const IDENTITY = "Identity";
const SKIPCHAIN = "Skipchain";
const POP = "PoPServer";
const CISC = "Cisc";


/**
 * Status Requests
 */
const STATUS_REQUEST = `Request`;

/**
 * Identity Requests
 */
const IDENTITY_PIN_REQUEST = `PinRequest`;
const IDENTITY_DATA_UPDATE = `DataUpdate`;
const IDENTITY_PROPOSE_UPDATE = `ProposeUpdate`;
const IDENTITY_PROPOSE_SEND = `ProposeSend`;
const IDENTITY_PROPOSE_VOTE = `ProposeVote`;

/**
 * Skipchain Requests
 */
const SKIPCHAIN_GET_UPDATE_CHAIN = `GetUpdateChain`;
const SKIPCHAIN_GET_ALL_SKIPCHAINS = `GetAllSkipchains`;

/**
 * PoP Requests
 */
const POP_STORE_CONFIG = `StoreConfig`;
const POP_FINALIZE_REQUEST = `FinalizeRequest`;
const POP_FETCH_REQUEST = `FetchRequest`;
const POP_PIN_REQUEST = `PinRequest`;
const POP_GET_PROPOSALS = 'GetProposals';
const POP_CHECK_CONFIG = 'CheckConfig';
const POP_VERIFY_LINK = 'VerifyLink';

/**
 * CISC Requests
 */
const CISC_CONFIG = `Config`;
const CISC_CONFIG_UPDATE = `ConfigUpdate`;
const CISC_DEVICE = `Device`;
const CISC_PROPOSE_VOTE = `ProposeVote`;
const CISC_PROPOSE_SEND = `ProposeSend`;
const CISC_PROPOSE_UPDATE = `ProposeUpdate`;
const CISC_SCHNORR_SIG = `SchnorrSig`;

// Exports --------------------------------------------------------------------
module.exports.STATUS = STATUS;
module.exports.IDENTITY = IDENTITY;
module.exports.SKIPCHAIN = SKIPCHAIN;
module.exports.POP = POP;
module.exports.CISC = CISC;
module.exports.STATUS_REQUEST = STATUS_REQUEST;
module.exports.IDENTITY_PIN_REQUEST = IDENTITY_PIN_REQUEST;
module.exports.IDENTITY_DATA_UPDATE = IDENTITY_DATA_UPDATE;
module.exports.IDENTITY_PROPOSE_UPDATE = IDENTITY_PROPOSE_UPDATE;
module.exports.IDENTITY_PROPOSE_SEND = IDENTITY_PROPOSE_SEND;
module.exports.SKIPCHAIN_GET_UPDATE_CHAIN = SKIPCHAIN_GET_UPDATE_CHAIN;
module.exports.SKIPCHAIN_GET_ALL_SKIPCHAINS = SKIPCHAIN_GET_ALL_SKIPCHAINS;
module.exports.POP_STORE_CONFIG = POP_STORE_CONFIG;
module.exports.POP_FINALIZE_REQUEST = POP_FINALIZE_REQUEST;
module.exports.POP_FETCH_REQUEST = POP_FETCH_REQUEST;
module.exports.POP_PIN_REQUEST = POP_PIN_REQUEST;
module.exports.POP_GET_PROPOSALS = POP_GET_PROPOSALS;
module.exports.POP_CHECK_CONFIG = POP_CHECK_CONFIG;
module.exports.CISC_CONFIG = CISC_CONFIG;
module.exports.CISC_CONFIG_UPDATE = CISC_CONFIG_UPDATE;
module.exports.CISC_DEVICE = CISC_DEVICE;
module.exports.CISC_PROPOSE_VOTE = CISC_PROPOSE_VOTE;
module.exports.CISC_PROPOSE_SEND = CISC_PROPOSE_SEND;
module.exports.CISC_PROPOSE_UPDATE = CISC_PROPOSE_UPDATE;
module.exports.CISC_SCHNORR_SIG = CISC_SCHNORR_SIG;
module.exports.IDENTITY_PROPOSE_VOTE = IDENTITY_PROPOSE_VOTE;
module.exports.POP_VERIFY_LINK = POP_VERIFY_LINK;
