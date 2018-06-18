const ScanToReturn = require("../../../shared/lib/scan-to-return/scan-to-return");
const Frame = require("ui/frame");
const Dialog = require("ui/dialogs");
const Timer = require("timer");
const ObservableModule = require("data/observable");
const ObservableArray = require("data/observable-array").ObservableArray;
const FileIO = require("../../../shared/lib/file-io/file-io");
const FilePaths = require("../../../shared/res/files/files-path");
const AttParty = require("../../../shared/lib/dedjs/object/pop/att/AttParty").Party;
const Convert = require("../../../shared/lib/dedjs/Convert");
const PartyStates = require("../../../shared/lib/dedjs/object/pop/att/AttParty").States;
const PoP = require("../../../shared/lib/dedjs/object/pop/PoP").get;

let loaded = false;
const viewModel = ObservableModule.fromObject({
  partyListDescriptions: new ObservableArray(),
  isLoading: false,
  isEmpty: true
});

let page = undefined;
let timerId = undefined;
let pageObject = undefined;

function onNavigatingTo(args) {
  pageObject = args.object.page;
}

function onLoaded(args) {
  page = args.object;

  page.bindingContext = viewModel;

  if (!loaded) {
    loadParties();
    loaded = true;
  }


  // Poll the status every 3s
  timerId = Timer.setInterval(() => {
    reloadStatuses();
  }, 5000)
}

function onUnloaded(args) {
  // remove polling when page is leaved
  Timer.clearInterval(timerId);
}

function loadParties() {
  viewModel.isLoading = true;

  // Bind isEmpty to the length of the array
  viewModel.partyListDescriptions.on(ObservableArray.changeEvent, () => {
    viewModel.set('isEmpty', viewModel.partyListDescriptions.length === 0);
  });

  let party = undefined;
  viewModel.partyListDescriptions.splice(0);
  FileIO.forEachFolderElement(FilePaths.POP_ATT_PATH, function (partyFolder) {
    party = new AttParty(partyFolder.name, true);
    // Observables have to be nested to reflect changes
    viewModel.partyListDescriptions.push(ObservableModule.fromObject({
      party: party,
      desc: party.getPopDescModule(),
      status: party.getPopStatusModule()
    }));
  });
  viewModel.isLoading = false;
}

function partyTapped(args) {
  const index = args.index;
  const status = viewModel.partyListDescriptions.getItem(index).status.status;
  const party = viewModel.partyListDescriptions.getItem(index).party;
  switch (status) {
    case PartyStates.ERROR:
      Dialog.alert({
        title: "Error",
        message: "The conode is offline, please wait until it comes online.",
        okButtonText: "Ok"
      });
      break;
    case PartyStates.PUBLISHED:
    case PartyStates.FINALIZING:
      Dialog
        .action({
          message: "What do you want to do ?",
          cancelButtonText: "Cancel",
          actions: ["Generate a new key pair", "Show the QR Code of my public key", "Display Party Info"]
        })
        .then(result => {
          if (result === "Generate a new key pair") {
            return Dialog.confirm({
              title: "Warning !",
              message: "The current key pair will by overwritten, so will need to get the new one " +
              "registered by the organizers. Are you sure you want to continue ?",
              okButtonText: "Yes",
              cancelButtonText: "No",
            })
              .then(accepted => {
                return !accepted ? Promise.resolve() : party.randomizeKeyPair()
                  .then(() => {
                    return Dialog.alert({
                      title: "A new key pair has been generated !",
                      message: "You can now use it to register to this party.",
                      okButtonText: "Ok"
                    })
                  })
              })
          } else if (result === "Show the QR Code of my public key") {
            Frame.topmost().currentPage.showModal("shared/pages/qr-code/qr-code-page", {
              textToShow: Convert.objectToJson(party.getKeyPair()),
              title: "Key Pair"
            }, () => {
            }, true);
          } else if (result === "Display Party Info") {
            Frame.topmost().navigate({
              moduleName: "drawers/pop/org/config/config-page",
              context: {
                party: party,
                readOnly: true
              }
            });
          }
        })
        .catch((error) => {
          Dialog.alert({
            title: "Error",
            message: "An error occured, please try again. - " + error,
            okButtonText: "Ok"
          });
          console.log(error);
          console.dir(error);
          console.trace(error);
        });
      break;
    case PartyStates.FINALIZED:
      Dialog
        .action({
          message: "The party is finished ! What do you want to do ?",
          cancelButtonText: "Cancel",
          actions: ["Generate my PoP-Token"]
        })
        .then(result => {
          if (result === "Generate my PoP-Token") {
            if (!party.isAttendee(party.getKeyPair().public)) {
              return Promise.reject("You are not part of the attendees.");
            }
            return PoP.addPopTokenFromFinalStatement(party.getFinalStatement(), party.getKeyPair(), true)
              .then(() => {
                return party.remove();
              })
              .then(() => {
                viewModel.partyListDescriptions.splice(index, 1);
                return Dialog.alert({
                  title: "Success !",
                  message: "Your Token is now accessible under \"My Tokens\".",
                  okButtonText: "Ok"
                });
              });
          }
        })
        .catch((error) => {
          Dialog.alert({
            title: "Error",
            message: error,
            okButtonText: "Ok"
          });
          console.log(error);
          console.dir(error);
          console.trace(error);
        });
      break;
    default:
      Dialog.alert({
        title: "Not implemented",
        okButtonText: "Ok"
      })
  }
}

function deleteParty(args) {
  const party = args.object.bindingContext;
  party.remove()
    .then(() => {
      const listView = Frame.topmost().currentPage.getViewById("listView");
      listView.notifySwipeToExecuteFinished();

      return Promise.resolve();
    })
    .catch((error) => {
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

function onSwipeCellStarted(args) {
  const swipeLimits = args.data.swipeLimits;
  const swipeView = args.object;

  const deleteButton = swipeView.getViewById("button-delete");

  const width = deleteButton.getMeasuredWidth();

  swipeLimits.right = width;
  swipeLimits.threshold = width / 2;
}

function addParty() {
  return ScanToReturn.scan()
    .then(string => {
      const infos = Convert.jsonToObject(string);
      const newParty = new AttParty(infos.id, false, infos.address);
      viewModel.partyListDescriptions.push(ObservableModule.fromObject({
        party: newParty,
        desc: newParty.getPopDescModule(),
        status: newParty.getPopStatusModule()
      }));

      return Promise.resolve();
    })
    .catch(error => {
      console.log(error);
      console.dir(error);
      console.trace();
      if (error !== ScanToReturn.SCAN_ABORTED) {
        setTimeout(() => {
          Dialog.alert({
            title: "Error",
            message: "An error occured, please try again. - " + error,
            okButtonText: "Ok"
          });
        });
      }

      return Promise.reject(error);
    });

}

function reloadStatuses() {
  viewModel.partyListDescriptions.forEach(model => {
    model.party.retrieveFinalStatementAndStatus();
  })
}


module.exports.onLoaded = onLoaded;
module.exports.partyTapped = partyTapped;
module.exports.onSwipeCellStarted = onSwipeCellStarted;
module.exports.deleteParty = deleteParty;
module.exports.addParty = addParty;
module.exports.onUnloaded = onUnloaded;
module.exports.onNavigatingTo = onNavigatingTo;
