const Frame = require("ui/frame");
const Dialog = require("ui/dialogs");
const ObservableModule = require("data/observable");
const Convert = require("../../../shared/lib/dedjs/Convert");
const Pop = require("../../../shared/lib/dedjs/object/pop/PoP").get;

const User = require("../../../shared/lib/dedjs/object/user/User").get;
let Party = undefined;

const topmost = require("ui/frame").topmost;

let viewModel = undefined;

let page = undefined;

function onLoaded(args) {
  page = args.object;

  const context = page.navigationContext;

  if(context.party === undefined) {
    throw new Error("Party should be given in the context");
  }

  Party = context.party;
  viewModel = ObservableModule.fromObject({
    linkedConode: Party.getLinkedConodeModule(),
    hash: Party.getPopDescHashModule(),
    toHex: Convert.byteArrayToHex
  });

  // This is to ensure that the hash will be updated in the UI when coming back from the config.
  page.bindingContext = undefined;
  page.bindingContext = viewModel;
}

function linkToConode() {
  if (!User.isKeyPairSet()) {
    return Dialog.alert({
      title: "Key Pair Missing",
      message: "Please generate a key pair.",
      okButtonText: "Ok"
    });
  }

  const conodes = User.getRoster().list;
  const conodesNames = conodes.map(serverIdentity => {
    return serverIdentity.description + " - " + Convert.byteArrayToHex(serverIdentity.id);
  });

  let index = undefined;

  return Dialog.action({
    message: "Choose a Conode",
    cancelButtonText: "Cancel",
    actions: conodesNames
  })
    .then(result => {
      if (result !== "Cancel") {
        index = conodesNames.indexOf(result);

        return Party.linkToConode(conodes[index], "")
          .then(result => {
            return Dialog.prompt({
              title: "Requested PIN",
              message: result,
              okButtonText: "Link",
              cancelButtonText: "Cancel",
              defaultText: "",
              inputType: Dialog.inputType.text
            })
          })
          .then(result => {
            if (result.result) {
              return Party.linkToConode(conodes[index], result.text)
                .then(result => {
                  // This is to ensure that id and public will be updated in the UI when linking process is done.
                  page.bindingContext = undefined;
                  page.bindingContext = viewModel;

                  return Dialog.alert({
                    title: "Success",
                    message: "Your are now linked to the conode.",
                    okButtonText: "Configure the party"
                  });
                });
            } else {
              return Promise.resolve();
            }
          });
      } else {
        return Promise.resolve();
      }
    })
    .catch(error => {
      console.log(error);
      console.dir(error);
      console.trace();

      Dialog.alert({
        title: "Error",
        message: "An unexpected error occurred. Please try again. - " + error,
        okButtonText: "Ok"
      });

      return Promise.reject(error);
    });
}

/**
 * Function called when the organizer wants to enter his config/description of the PoP Party.
 */
function configButtonTapped() {
  Frame.topmost().navigate({
    moduleName: "drawers/pop/org/config/config-page",
    context: {
      party: Party
    }
  });
}

/**
 * Function called when the organizer wants to register the keys of the attendees.
 */
function registerButtonTapped() {
  Frame.topmost().navigate({
    moduleName: "drawers/pop/org/register/register-page",
    context: {
      party: Party
    }
  });
}

/**
 * Function called when the organizer wants to fetch the final statement of the PoP Party.
 * @returns {*|Promise.<any>}
 */
function fetchButtonTapped() {
  if (!Party.isLinkedConodeSet()) {
    return Dialog.alert({
      title: "Not Linked to Conode",
      message: "Please link to a conode first.",
      okButtonText: "Ok"
    });
  }

  const popDescId = Party.getPopDescHash();
  if (popDescId.length === 0) {
    return Dialog.alert({
      title: "PoP-Description Hash Missing",
      message: "You have to register your PoP-Description first.",
      okButtonText: "Ok"
    });
  }

  return Pop.fetchFinalStatement(Party.getLinkedConode(), popDescId)
    .then(() => {
      return Dialog.alert({
        title: "Final Statement Saved",
        message: "The fetched final statement can be found in the PoP tab.",
        okButtonText: "Ok"
      });
    })
    .catch(error => {
      console.log(error);
      console.dir(error);
      console.trace();

      Dialog.alert({
        title: "Error",
        message: "An unexpected error occurred. Please try again. - " + error,
        okButtonText: "Ok"
      });

      return Promise.reject(error);
    });
}

function removeButtonTapped() {
  Party.remove();
  topmost().goBack();
}

module.exports.onLoaded = onLoaded;
module.exports.configButtonTapped = configButtonTapped;
module.exports.registerButtonTapped = registerButtonTapped;
module.exports.fetchButtonTapped = fetchButtonTapped;
module.exports.linkToConode = linkToConode;
module.exports.removeButtonTapped = removeButtonTapped;
