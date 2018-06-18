const Dialog = require("ui/dialogs");

const Cisc = require("~/shared/lib/dedjs/object/cisc/Cisc").Skipchain;
const mockCisc = new Cisc("MOCK2");

const viewModel = mockCisc.getVMModule();

function onLoaded(args) {
  const page = args.object;
  page.bindingContext = viewModel;
}

function resetCisc() {
    return Dialog.confirm({
        title: "ALERT",
        message: "You are about to completely reset the Cisc service, this action can NOT be undone! Please confirm.",
        okButtonText: "Reset",
        cancelButtonText: "Cancel"
    })
        .then(result => {
            if (result) {
                return Cisc.reset()
                    .then(() => {
                        return Dialog.alert({
                            title: "Cisc Has Been Reset",
                            message: "Everything belonging to the Cisc service has been completely reset.",
                            okButtonText: "Ok"
                        });
                    });
            }

            return Promise.resolve();
        })
        .catch(() => {
            console.log(error);
            console.dir(error);
            console.trace();

            Dialog.alert({
                title: "Error",
                message: "An unexpected error occurred. Please try again.",
                okButtonText: "Ok"
            });

            return Promise.reject(error);
        });
}

function disconnectCisc(){
    return mockCisc.setIsConnected(false);
}

function chooseName() {
    if (viewModel.name === "") {
        return Dialog.alert({
            title: "Error",
            message: "Name can't be empty",
            okButtonText: "OK"
        });
    }
    mockCisc.setName(viewModel.name,true)
        .then(() => Dialog.alert({
            title: "Name successfully changed",
            message: `Your're name has been set to "${viewModel.name}"`,
            okButtonText: "OK"
        }))
        .catch((error) => {
        console.log(error);
        Dialog.alert({
            title: "Error",
            message: "An error occured please try again",
            okButtonText:"OK"
        });
    });
}


exports.onLoaded = onLoaded;
exports.chooseName = chooseName;
exports.resetCisc = resetCisc;
exports.disconnectCisc = disconnectCisc;
