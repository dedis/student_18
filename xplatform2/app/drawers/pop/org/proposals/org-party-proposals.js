const Dialog = require("ui/dialogs");
const ObservableArray = require("data/observable-array").ObservableArray;
const topmost = require("ui/frame").topmost;
const Net = require("@dedis/cothority").net;
const Convert = require("../../../../shared/lib/dedjs/Convert");
const DecodeType = require("../../../../shared/lib/dedjs/network/DecodeType");
const RequestPath = require("../../../../shared/lib/dedjs/network/RequestPath");
const OrgParty = require("../../../../shared/lib/dedjs/object/pop/org/OrgParty").Party;

let conodeAddress = undefined;

let viewModel =  {
  proposals: new ObservableArray()
};

function onLoaded(args) {
  const page = args.object;
  const context = page.navigationContext;

  page.bindingContext = viewModel;

  if (context.conode === undefined) {
    throw new Error("Conode address should be given in the context");
  }

  conodeAddress = context.conode;

  retrieveProposals();

}

function retrieveProposals() {
  viewModel.proposals.splice(0);
  const cothoritySocket = new Net.Socket(Convert.tlsToWebsocket(conodeAddress, ""), RequestPath.POP);

  return cothoritySocket.send(RequestPath.POP_GET_PROPOSALS, DecodeType.GET_PROPOSALS_REPLY, {})
    .then(response => {
      viewModel.proposals.push(response.proposals);
      return Promise.resolve();
    })
    .catch(error => {
      console.log(error);
      console.dir(error);
      console.trace();

      Dialog.alert({
        title: "Error",
        message: "An error occured, please try again. - " + error,
        okButtonText: "Ok"
      });


      return Promise.reject(error);
    });
}
hashAndSave = require("../org-party-list").hashAndSave;
const addMyselfAttendee = require("../register/register-page").addMyselfAttendee;
function proposalTapped(args) {
  const index = args.index;

  // create the party
  let party = new OrgParty();
  let promises = [
    party.setPopDesc(viewModel.proposals.getItem(index), true),
    party.setLinkedConode(conodeAddress, true)
  ];
  Promise.all(promises)
    .then(() => {
        hashAndSave(party);
        addMyselfAttendee(party);
      goBack();
      return Promise.resolve();
    })
    .catch(error => {
      Dialog.alert({
        title: "Error",
        message: "An error occured, please try again. - " + error,
        okButtonText: "Ok"
      });

      return Promise.reject(error);
    });

}

function goBack() {
  topmost().goBack();
}

module.exports.goBack = goBack;
module.exports.onLoaded = onLoaded;
module.exports.proposalTapped = proposalTapped;