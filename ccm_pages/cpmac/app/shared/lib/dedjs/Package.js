/**
 * @file File containing package paths. They are used to uniquely create symbols which are then used for singletons.
 */

const DEDIS = "ch.epfl.dedis";
const APP = `${DEDIS}.cpmac`;

/**
 * User
 */
const USER = `${APP}.user`;

/**
 * PoP
 */
const POP = `${APP}.pop`;
const ORG = `${POP}.org`;
const ATT = `${POP}.att`;

/**
 * Cisc
 */
const CISC = `${APP}.cisc`;

module.exports.USER = USER;
module.exports.POP = POP;
module.exports.ORG = ORG;
module.exports.ATT = ATT;
module.exports.CISC = CISC;