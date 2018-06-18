const FrameModule = require("ui/frame");
const Dialog = require("ui/dialogs");
const RequestPath = require("~/shared/lib/dedjs/network/RequestPath");
const CothorityMessages = require("~/shared/lib/dedjs/network/cothority-messages");
const DecodeType = require("~/shared/lib/dedjs/network/DecodeType");
const Convert = require("~/shared/lib/dedjs/Convert");
const Helper = require("~/shared/lib/dedjs/Helper");
const Cisc = require("~/shared/lib/dedjs/object/cisc/Cisc").skipchain;
const NetDedis = require("@dedis/cothority").net;
const LabelModule = require("tns-core-modules/ui/label");
const SkipPage = require("../skipchain-page");
const ObservableArray = require("data/observable-array").ObservableArray;
const ObservableModule = require("data/observable");

let Page;
let page;
let skipchain;

const viewModel = ObservableModule.fromObject({
  skipchainVMModule: new ObservableArray(),
  certList: new ObservableArray(),
  isLoading: false
});
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
    page = args.object;
    Page = page.page;
    viewModel.skipchainVMModule = skipchain.getVMModule();
    loadCert();

    page.bindingContext = viewModel;
    viewmodel = page.bindingContext;

}

function isCert(cert) {
    return cert.startsWith("-----BEGIN CERTIFICATE-----") && 
            cert.includes("-----END CERTIFICATE-----");
}

function loadCert() {
    viewModel.isLoading = true;
    viewModel.certList.splice(0);

    for (var key in skipchain.getData().storage) {
        if (skipchain.getData().storage.hasOwnProperty(key) && 
            isCert(skipchain.getData().storage[key])) {
            viewModel.certList.push(ObservableModule.fromObject({
                certKey: key,
                cert : skipchain.getData().storage[key]
            }));
        }
    }    
    viewModel.isLoading = false;
}

function certTapped(args){
    console.log("Touched");
    const index = args.index;
    const cert = viewModel.certList.getItem(index).cert;

    FrameModule.topmost().navigate({
        moduleName: "drawers/cisc/cert/cert-details/cert-details",
        context: {
            cert: cert
        }
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

exports.loadCert = loadCert;
exports.certTapped = certTapped;
exports.onLoaded = onLoaded;
exports.onDrawerButtonTap = onDrawerButtonTap;

