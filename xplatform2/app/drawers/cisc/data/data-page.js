const FrameModule = require("ui/frame");
const Dialog = require("ui/dialogs");
const RequestPath = require("~/shared/lib/dedjs/network/RequestPath");
const CothorityMessages = require("~/shared/lib/dedjs/network/cothority-messages");
const DecodeType = require("~/shared/lib/dedjs/network/DecodeType");
const Convert = require("~/shared/lib/dedjs/Convert");
const Helper = require("~/shared/lib/dedjs/Helper");
const Cisc = require("~/shared/lib/dedjs/object/cisc/Cisc").Skipchain;
const Net = require("@dedis/cothority").net;
const SkipPage = require("../skipchain-page");
const Kyber = require("@dedis/kyber-js");
const User = require("../../../shared/lib/dedjs/object/user/User").get;

let skipchain;
let viewmodel;
let Page;

/* ***********************************************************
 * Use the "onNavigatingTo" handler to initialize the page binding context.
 *************************************************************/
function onLoaded(args) {
    /* ***********************************************************
     * The "onNavigatingTo" event handler lets you detect if the user navigated with a back button.
     * Skipping the re-initialization on back navigation means the user will see the
     * page in the same data state that he left it in before navigating.
     *************************************************************/
    if (args.isBackNavigation) {
        return;
    }

    skipchain = SkipPage.skipchain.elem;
    const page = args.object;
    Page = page.page;
    page.bindingContext = skipchain.getVMModule();
    viewmodel = page.bindingContext;
}

function addKeyValue() {
    let key;
    let value;
    let proposeSendMessage;
    let edited;

    return Dialog.prompt({
        title: "Key",
        message: "What is the key you want to add ?",
        okButtonText: "Ok",
        cancelButtonText: "Cancel",
        inputType: Dialog.inputType.text
    })
        .then((response) => {
            if (response.result) {
                key = response.text;
                return Dialog.prompt({
                    title: "Value",
                    message: `What is the value that goes with ${key}`,
                    okButtonText: "Ok",
                    cancelButtonText: "Cancel",
                    inputType: Dialog.inputType.text
                })
            }
        })
        .then((response) => {
            if (response.result) {
                value = response.text;
                edited = Helper.deepCopy(skipchain.getData());
                if (edited.storage === null || edited.storage === undefined) {
                    edited.storage = {};
                }
                edited.storage[key]=value;
                edited.votes = null;

                proposeSendMessage = CothorityMessages.createProposeSend(Convert.hexToByteArray(skipchain.getIdentity().id), edited);
                const cothoritySocket = new Net.Socket(Convert.tlsToWebsocket(skipchain.getIdentity().address, ""), RequestPath.IDENTITY);
                return cothoritySocket.send(RequestPath.IDENTITY_PROPOSE_SEND, DecodeType.DATA_UPDATE_REPLY, proposeSendMessage)
            }
        })
        .then(()=>{
            return skipchain.updateAll().then(()=>skipchain.voteForProposed());
        })
        .catch((error) => {
            console.log(error);
            console.dir(error);
            console.trace();
        });
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

exports.onLoaded = onLoaded;
exports.onDrawerButtonTap = onDrawerButtonTap;
exports.addKeyValue = addKeyValue;
