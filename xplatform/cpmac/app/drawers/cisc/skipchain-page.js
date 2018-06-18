const frameModule = require("ui/frame");
const Cisc = require("../../shared/lib/dedjs/object/cisc/Cisc").Skipchain;
const FilePaths = require("../../shared/res/files/files-path");
const FileIO = require("../../shared/lib/file-io/file-io");

/* ***********************************************************
 * Use the "onNavigatingTo" handler to initialize the page binding context.
 *************************************************************/
const skipchain = {}

function onNavigatingTo(args) {

    if (args.isBackNavigation) {
        return;
    }

    page = args.object;
    const context = page.navigationContext;

    skipchain.elem = context.skipchain.skipchain;

    const viewmodel = context.skipchain;
    page.bindingContext = viewmodel;
}

/* ***********************************************************
 * According to guidelines, if you have a drawer on your page, you should always
 * have a button that opens it. Get a reference to the RadSideDrawer view and
 * use the showDrawer() function to open the app drawer section.
 *************************************************************/
function onDrawerButtonTap(args) {
    const sideDrawer = frameModule.topmost().getViewById("sideDrawer");
    sideDrawer.showDrawer();
}

exports.skipchain = skipchain;
exports.onNavigatingTo = onNavigatingTo;
exports.onDrawerButtonTap = onDrawerButtonTap;