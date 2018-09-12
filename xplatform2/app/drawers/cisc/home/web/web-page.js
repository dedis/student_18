const frameModule = require("ui/frame");
const webViewModule = require("ui/web-view");
const Dialog = require("ui/dialogs");

let page;
let wv;

function onNavigatingTo(args) {
    /* ***********************************************************
     * The "onNavigatingTo" event handler lets you detect if the user navigated with a back button.
     * Skipping the re-initialization on back navigation means the user will see the
     * page in the same data state that he left it in before navigating.
     *************************************************************/
    if (args.isBackNavigation) {
        return;
    }

    page = args.object;
    setView();
    let bindingContext = page.bindingContext;
    console.dir(bindingContext);
    wv.on(webViewModule.WebView.loadStartedEvent, function(event) {

        // Check if the WebView is trying to navigate to 'web:'
        if (event.url.indexOf('web:') === 0 ) {
            // Stop the loading event
            if (event.object.ios) {
                event.object.ios.stopLoading();
            } else if (event.object.android) {
                event.object.android.stopLoading();
            }

            // Do something depending on the coordinates in the URL
            let isIn = false;
            let item;
            for (let i=0; i<bindingContext.data.length; i++ ){
                item = bindingContext.data.getItem(""+i).keyValuePair;
                console.log(item.key);
                console.log(event.url);
                if (item.key === event.url) {
                    isIn = true;
                    break;
                }
            }

            if (isIn) {
                wv.src = item.value;
            } else {
                Dialog.alert({
                    title: "Error",
                    message:"This page is not available on this identity",
                    okButtonText: "Ok"
                })
            }
        }
    });
}

function setView() {
    wv = page.getViewById("webweb")
}

function onDrawerButtonTap(args) {
    const sideDrawer = frameModule.topmost().getViewById("sideDrawer");
    sideDrawer.showDrawer();
}

exports.onNavigatingTo = onNavigatingTo;
exports.onDrawerButtonTap = onDrawerButtonTap;
