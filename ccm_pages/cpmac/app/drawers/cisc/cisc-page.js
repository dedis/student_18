const FrameModule = require("ui/frame");
const Cisc = require("../../shared/lib/dedjs/object/cisc/Cisc").Skipchain;
const FilePaths = require("../../shared/res/files/files-path");
const FileIO = require("../../shared/lib/file-io/file-io");
const ObservableModule = require("data/observable");
const ObservableArray = require("data/observable-array").ObservableArray;
const BarcodeScanner = require("nativescript-barcodescanner").BarcodeScanner;
const CothorityMessages = require("~/shared/lib/dedjs/network/cothority-messages");
const User = require("~/shared/lib/dedjs/object/user/User").get;
const Dialog = require("ui/dialogs");
const Helper = require("~/shared/lib/dedjs/Helper");
const Convert = require("~/shared/lib/dedjs/Convert");
const Net = require("@dedis/cothority").net;
const RequestPath = require("~/shared/lib/dedjs/network/RequestPath");
const DecodeType = require("~/shared/lib/dedjs/network/DecodeType");

const skipchainsArray = [];
const viewModel = ObservableModule.fromObject({
    skipchainsList: new ObservableArray(),
    isLoading: false
});
/* ***********************************************************
 * Use the "onNavigatingTo" handler to initialize the page binding context.
 *************************************************************/
function onNavigatingTo(args) {
    /* ***********************************************************
     * The "onNavigatingTo" event handler lets you detect if the user navigated with a back button.
     * Skipping the re-initialization on back navigation means the user will see the
     * page in the same data state that he left it in before navigating.
     *************************************************************/
    if (args.isBackNavigation) {
        return;
    }

    const page = args.object;
    page.bindingContext = viewModel;
    if (skipchainsArray.length == 0){
        createSkipchains();
        setTimeout(() => {
            loadSkipchains();
        },0);
    }
}

function createSkipchains() {
    FileIO.forEachFolderElement(FilePaths.CISC_PATH, function (ciscFolder) {
        skipchainsArray.push(new Cisc(ciscFolder.name));
    });

}

function loadSkipchains() {
    const bytesLimit = 32;
    viewModel.isLoading = true;
    let skipchain = undefined;
    viewModel.skipchainsList.splice(0);

    for (var i = 0; i < skipchainsArray.length; i++) {
        viewModel.skipchainsList.push(ObservableModule.fromObject({
            skipchain: skipchainsArray[i],
            identity: skipchainsArray[i].getIdentity(),
            idSimple: (skipchainsArray[i].getIdentity().id).substring(0, bytesLimit-1),
            skipchainName: skipchainsArray[i].getIdentity().name
        }));
    }    
    viewModel.isLoading = false;
}


function skipchainTapped(args) {
    const index = args.index;
    const skipchain = viewModel.skipchainsList.getItem(index);

    FrameModule.topmost().navigate({
        moduleName: "drawers/cisc/skipchain-page",
        context: {
            skipchain: skipchain
        }
    });
}

function connectButtonTapped(args) {
    const scName = User.getName();
    const barcodescanner = new BarcodeScanner();
    if (scName === null || scName === undefined || scName === "") {
        throw new Error("Go to the settings to set your name")
    }
    if (!(User.isKeyPairSet())) {
        throw new Error("Go to the settings to generate a keypair")
    }
    return barcodescanner.available()
        .then(function (available) {
            if (available) {
                Dialog.prompt({
                    title: "Information",
                    message: "Give your skipchain a name",
                    okButtonText: "Ok",
                    cancelButtonText: "Cancel"
                }).then(function (r) {
                    if(r.result){
                        return availableFunction(r.text);
                    }
                });
                
            } else {
                return notAvailableFunction();
            }
        })
        .catch((error) => {
            console.log(error);
            setTimeout(() => Dialog.alert({
                title: "Scanner Error",
                message: error.toString(),
                okButtonText: "Ok"
            }), 100)
        });

    function availableFunction(identityName) {
        return barcodescanner.scan({
            formats: "QR_CODE", // Pass in of you want to restrict scanning to certain types
            cancelLabel: "EXIT. Also, try the volume buttons!", // iOS only, default 'Close'
            cancelLabelBackgroundColor: "#333333", // iOS only, default '#000000' (black)
            message: "Use the volume buttons for extra light", // Android only, default is 'Place a barcode inside the viewfinder rectangle to scan it.'
            showFlipCameraButton: true, // default false
            preferFrontCamera: false, // default false
            showTorchButton: true, // default false
            beepOnScan: true, // Play or Suppress beep on scan (default true)
            torchOn: false, // launch with the flashlight on (default false)
            closeCallback: function () {
                console.log("Scanner closed");
            }, // invoked when the scanner was closed (success or abort)
            resultDisplayDuration: 500, // Android only, default 1500 (ms), set to 0 to disable echoing the scanned text
            orientation: "portrait", // Android only, optionally lock the orientation to either "portrait" or "landscape"
            openSettingsIfPermissionWasPreviouslyDenied: true // On iOS you can send the user to the settings app if access was previously denied
        }).then(
            (result) => {
                const newSkipchain = new Cisc();

                console.dir(result);
                const splitColon = result.text.split(":");
                const splitSlash = splitColon[2].split("/");
                const goodURL = `tls:${splitColon[1]}:${splitSlash[0]}`;

                let label = result.text;
                let address = goodURL;
                let id = `${splitSlash[1]}`;
                setTimeout(() => {
                    skipchainsArray.push(newSkipchain);
                    viewModel.skipchainsList.push(ObservableModule.fromObject({
                        skipchain: newSkipchain,
                        identity: newSkipchain.getIdentity(),
                        idSimple: (newSkipchain.getIdentity().id).substring(0, 31),
                        skipchainName: identityName
                    }));
                },10);

                newSkipchain.setName(User.getName(), true);
                newSkipchain.setIdentity(id, address, label, identityName, true)
                   .then(() => askForDevice(newSkipchain));
            })
            .catch(
                (error) => setTimeout(() => Dialog.alert({
                    title: "Scanner Error",
                    message: error.toString(),
                    okButtonText: "Ok"
                }), 100)
            );
    }

    function notAvailableFunction() {
        return Dialog.alert({
            title: "Where is your camera?",
            message: "There is no camera available on your phone.",
            okButtonText: "Ok"
        });
    }
}

function askForDevice(newSkipchain) {
    return newSkipchain.updateAll().then(() => {
        console.log("checking for device");
        let isIn = false;
        for (let i = 0; i < newSkipchain.getDevices().length; i++) {
            let device = newSkipchain.getDevices().getItem("" + i).device;
            if (device.id === newSkipchain.getName() && device.point === Convert.byteArrayToHex(User.getKeyPairModule().public)) {
                isIn = true;
            }
        }
        if (isIn) {
            return Dialog.alert({
                title: "Connection successful",
                message: "You successfully connected to this identity!",
                okButtonText: "Ok"
            })
        } else {
            return Dialog.confirm({
                title: "First Connection",
                message: "Do you want to add this device to the identity ?",
                okButtonText: "yes",
                cancelButtonText: "no"
            })
        }
    })
        .then((result) => {
            if (result) {
                addDevice(newSkipchain);
            }
        })
        .catch((error) => console.log(error));
}

function addDevice(newSkipchain) {
    let data = Helper.deepCopy(newSkipchain.getData());
    data.device[newSkipchain.getName()] = CothorityMessages.createDevice(User.getKeyPairModule().public);
    data.votes = {};
    console.dir(data);

    let proposeSendMessage = CothorityMessages.createProposeSend(Convert.hexToByteArray(newSkipchain.getIdentity().id), data);
    console.log(newSkipchain.getIdentity().id);
    const cothoritySocket = new Net.Socket(Convert.tlsToWebsocket(newSkipchain.getIdentity().address, ""), RequestPath.IDENTITY);
    cothoritySocket.send(RequestPath.IDENTITY_PROPOSE_SEND, DecodeType.DATA_UPDATE_REPLY, proposeSendMessage)
        .then((response) => {
            console.log(response);
            console.dir(response);
        })
        .catch((error) => {
            console.log(error);
            console.dir(error);
            console.trace();
        });
}

function disconnectSkipchain(args) {
    const delSkipchain = args.object.bindingContext._map.skipchain;
    const delIndex = skipchainsArray.findIndex(sc => sc === delSkipchain);
    skipchainsArray.splice(delIndex, 1);
    viewModel.skipchainsList.splice(delIndex,1);
    delSkipchain.setIsConnected(false);
    delSkipchain.remove()
    .then(() => {
        const listView = FrameModule.topmost().currentPage.getViewById("listView");
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

  swipeLimits.right = width * 1.2;
  swipeLimits.threshold = width / 2;
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

exports.onSwipeCellStarted = onSwipeCellStarted;
exports.disconnectSkipchain = disconnectSkipchain;
exports.connectButtonTapped = connectButtonTapped;
exports.skipchainTapped = skipchainTapped;
exports.skipchainsArray = skipchainsArray;
exports.onNavigatingTo = onNavigatingTo;
exports.onDrawerButtonTap = onDrawerButtonTap;