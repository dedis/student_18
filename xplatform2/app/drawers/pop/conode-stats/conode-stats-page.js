const Frame = require("ui/frame");
const Convert = require("../../../shared/lib/dedjs/Convert");
const ConodeStatsViewModel = require("./conode-stats-view-model");
const topmost = require("ui/frame").topmost;
const deleteConode = require ("../pop-page").deleteConode;
const conodeStatsViewModel = new ConodeStatsViewModel();
const loadConodeList = require("../pop-page").loadConodeList;
const deblockConodeList = require("../pop-page").deblockConodeList;
const myStatsList = conodeStatsViewModel.statsList;


let conode = undefined;
let conodeStatus = undefined;

let pageObject = undefined;

function onNavigatingTo(args) {
  const page = args.object;
  pageObject = page.page;
  conode = page.bindingContext.conode;
  conodeStatus = page.bindingContext.conodeStatus;

  page.bindingContext = conodeStatsViewModel;

  loadFunction(conodeStatus);
}

/**
 * Loads the properties of the selected conode into the list to display them to the user.
 * @param conodeStatus - the selected conode
 */
function loadFunction(conodeStatus) {
  myStatsList.empty();
  myStatsList.load(conodeStatus);
}

/**
 * Changes the frame to the QR displaying of the conodes.
 */
function displayQrOfConode() {
  pageObject.showModal("shared/pages/qr-code/qr-code-page", {
    textToShow: Convert.objectToJson(conode),
    title: "Conode informations"
  }, () => { }, true);
}

/**
 * Go back to the previous page
 */
function goBack() {
  topmost().goBack();
}

function deleteC(){

    deleteConode(conode);
  Frame.topmost().navigate({moduleName :"drawers/pop/pop-page" })


}


module.exports.onNavigatingTo = onNavigatingTo;
module.exports.displayQrOfConode = displayQrOfConode;
module.exports.goBack = goBack;
module.exports.deleteC=deleteC;