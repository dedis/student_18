const Dialog = require("ui/dialogs");
const Helper = require("../../lib/dedjs/Helper");
const NetUtils = require("../../lib/dedjs/network/NetUtils");
const ObservableModule = require("data/observable");

let textFieldAddress = undefined;

let closeCallBackFunction = undefined;

let viewModel = ObservableModule.fromObject({
  isLoading: false
});

function onShownModally(args) {
  closeCallBackFunction = args.closeCallback;
}

function onLoaded(args) {
  const page = args.object;

  loadViews(page);
  if (textFieldAddress === undefined) {
    throw new Error("a field is undefined, but it shouldn't");
  }
  page.bindingContext = viewModel
}

/**
 * Loads the needed views into their variables.
 * @param page - the current page object
 */
function loadViews(page) {
  textFieldAddress = page.getViewById("text-view-conode-address");
}

/**
 * Gets called when the user wants to add a conode manually, it converts the information given to a conode object
 * and sends it back to the description page.
 */
function addManual() {
  const address = textFieldAddress.text;

  if (address.length > 0) {
    const finalAddress = Helper.BASE_URL_TLS + address;
    try {
      if (!Helper.isValidAddress(finalAddress)) {
        return Dialog.alert({
          title: "Address of conode incorrect",
          message: "Please double check your address.",
          okButtonText: "Ok"
        });
      }

      viewModel.isLoading = true;

      return NetUtils.getServerIdentiyFromAddress(finalAddress)
        .then(server => {
          viewModel.isLoading = false;
          closeCallBackFunction(server);
        })
        .catch(error => {
          console.log(error);
          console.dir(error);
          viewModel.isLoading = false;
          return Dialog.alert({
            title: "Address or server incorrect",
            message: "Please double check your address.",
            okButtonText: "Ok"
          });

        })
    } catch (error) {
      console.log(error);
      console.dir(error);
      console.trace();
      viewModel.isLoading = false;

      return Dialog.alert({
        title: "Incorrect Input",
        message: "Please double check your address.",
        okButtonText: "Ok"
      });
    }
  } else {
    viewModel.isLoading = false;
    return Dialog.alert({
      title: "Provide the address",
      message: "Please provide the address of the conode.",
      okButtonText: "Ok"
    });
  }
}

/**
 * When the user wants to cancel the addition of a conode we simply get back to the description with an undefined
 * conode.
 */
function onCancel() {
  closeCallBackFunction(undefined);
}

exports.onShownModally = onShownModally;
exports.onLoaded = onLoaded;
exports.addManual = addManual;
exports.onCancel = onCancel;
