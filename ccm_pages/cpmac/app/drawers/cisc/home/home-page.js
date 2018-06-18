const FrameModule = require("ui/frame");
const Dialog = require("ui/dialogs");
const SkipPage = require("../skipchain-page");

let page = undefined;
let skipchain;
let viewmodel;

function onLoaded(args) {

    if (args.isBackNavigation) {
        return;
    }

    page = args.object;

    skipchain = SkipPage.skipchain.elem;
    viewmodel = skipchain.getVMModule();
    page.bindingContext = viewmodel;

}


/* ***********************************************************
 * According to guidelines, if you have a drawer on your page, you should always
 * have a button that opens it. Get a reference to the RadSideDrawer view and
 * use the showDrawer() function to open the app drawer section.
 *************************************************************/
function onDrawerButtonTap(args) {
    const sideDrawer = FrameModule.topmost().getViewById("sideDrawer");
    sideDrawer.showDrawer();
}

function toggleProposed() {

    let storage = page.getViewById("storage");
    let storageLabel = page.getViewById("storageLabel");
    let device = page.getViewById("device");
    let deviceLabel = page.getViewById("deviceLabel");

    let proposedStorage = page.getViewById("proposedStorage");
    let proposedStorageLabel = page.getViewById("proposedStorageLabel");
    let proposedDevice = page.getViewById("proposedDevice");
    let proposedDeviceLabel = page.getViewById("proposedDeviceLabel");

    skipchain.updateAll()
        .then(() => {
            if (proposedStorage.visibility === "collapse") {
                if (JSON.stringify(skipchain.getProposedData()) === "{}" ){
                    Dialog.alert({
                        title: "No data",
                        message: `There is no proposed data`,
                        okButtonText: "Ok"
                    });
                } else {
                    viewmodel.isOnProposed = true;
                }
            } else {
                viewmodel.isOnProposed = false;
            }
        });
}

function voteForProposed() {

    skipchain.voteForProposed()
        .then(() => {
            viewmodel.isOnProposed = false;
            skipchain.updateAll();
        })
        .catch((error) => {
                console.log(error);
                console.dir(error);
                console.trace();

                Dialog.alert({
                    title: "Error",
                    message: "Already signed or invalid operation",
                    okButtonText: "Ok"
                });
                throw new Error("Already signed or invalid operation")
            }
        );
}

function reloadData(args) {
    if(!viewmodel.isOnProposed){
        skipchain.updateAll()
            .catch((error) => {
                console.log(error);
                console.dir(error);
                console.trace(); 
            });
    }
}

exports.reloadData = reloadData;
exports.onLoaded = onLoaded;
exports.toggleProposed = toggleProposed;
exports.onDrawerButtonTap = onDrawerButtonTap;
exports.voteForProposed = voteForProposed;
