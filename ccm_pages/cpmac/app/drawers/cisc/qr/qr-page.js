const Frame = require("ui/frame");
const ZXing = require("nativescript-zxing");
const ImageSource = require("image-source");
const PlatformModule = require("tns-core-modules/platform");

const QRGenerator = new ZXing();

const Cisc = require("../../../shared/lib/dedjs/object/cisc/Cisc").Skipchain;
const SkipPage = require("../skipchain-page");

let skipchain;
let viewModel;
let image;
let label;

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
    const page = args.object;
    skipchain = SkipPage.skipchain.elem;
    page.bindingContext = skipchain.getVMModule();
    viewModel = page.bindingContext;
    loadViews(page);
    setTimeout(() => {
        updateImage()
    },500);
}

function updateImage() {
    if (skipchain.getIdentity().address !== "" && skipchain.getIsConnected()) {
        label.text = skipchain.getIdentity().label;
        const sideLength = PlatformModule.screen.mainScreen.widthPixels;
        const QR_CODE = QRGenerator.createBarcode({
            encode: label.text,
            format: ZXing.QR_CODE,
            height: sideLength,
            width: sideLength
        });

        image.imageSource = ImageSource.fromNativeSource(QR_CODE);
    }
}

function loadViews(page) {
    label = page.getViewById("label");
    image = page.getViewById("image");
}

/* ***********************************************************
 * According to guidelines, if you have a drawer on your page, you should always
 * have a button that opens it. Get a reference to the RadSideDrawer view and
 * use the showDrawer() function to open the app drawer section.
 *************************************************************/
function onDrawerButtonTap(args) {
    const sideDrawer = Frame.topmost().getViewById("sideDrawer");
    sideDrawer.showDrawer();
}


exports.onLoaded = onLoaded;
exports.onDrawerButtonTap = onDrawerButtonTap;
exports.updateImage = updateImage;
