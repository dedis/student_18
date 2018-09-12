const ScanToReturn = require("../../../shared/lib/scan-to-return/scan-to-return");
const Frame = require("ui/frame");
const Dialog = require("ui/dialogs");
const Timer = require("timer");
const ObservableModule = require("data/observable");
const ObservableArray = require("data/observable-array").ObservableArray;
const FileIO = require("../../../shared/lib/file-io/file-io");
const FilePaths = require("../../../shared/res/files/files-path");
const Convert = require("../../../shared/lib/dedjs/Convert");
const PartyStates = require("../../../shared/lib/dedjs/object/pop/att/AttParty").States;
const PoP = require("../../../shared/lib/dedjs/object/pop/PoP").get;
const Bar = require("../../../shared/lib/dedjs/object/beercoin/Bar").Bar;

const viewModel = ObservableModule.fromObject({
  barListDescriptions: new ObservableArray(),
  isLoading: false,
  isEmpty:true
});

let page = undefined;
let pageObject = undefined;

function onNavigatingTo(args) {
  pageObject = args.object.page;


}

function onLoaded(args) {
  page = args.object;

  page.bindingContext = viewModel;

  loadBars();

}

function loadBars() {
    viewModel.isLoading = true;

    // Bind isEmpty to the length of the array

    viewModel.barListDescriptions.on(ObservableArray.changeEvent, () => {
        viewModel.set('isRosterEmpty', viewModel.barListDescriptions.length === 0);
});
    let bar = undefined;
    viewModel.barListDescriptions.splice(0);
    FileIO.forEachFolderElement(FilePaths.BEERCOIN_PATH, function (barFolder) {
        bar = new Bar(barFolder.name);
        // Observables have to be nested to reflect changes
        viewModel.barListDescriptions.push(ObservableModule.fromObject({
            bar: bar,
            desc: bar.getConfigModule(),
        }));
    });
    viewModel.isLoading = false;
}

function barTapped(args) {
  const index = args.index;
  const bar = viewModel.barListDescriptions.getItem(index).bar;
  const signData = bar.getSigningData();
  const USER_CANCELED = "USER_CANCELED_STRING";
  Dialog
    .action({
      message: "What do you want to do ?",
      cancelButtonText: "Cancel",
      actions: ["Show service info to user", "Show orders history" , "Delete Service"]
    })
    .then(result => {
      if (result === "Show service info to user") {

          pageObject.showModal("shared/pages/qr-code/qr-code-page", {
            textToShow: Convert.objectToJson(signData),
            title: "Service information"
          },
             () => {

                 Dialog.confirm({
                     title: "Client confirmation",
                     message: "Do you want to also scan the client confirmation ?",
                     okButtonText: "Yes",
                     cancelButtonText: "No"
                 }).then(function (result) {
                     if (!result) {
                         return Promise.reject(USER_CANCELED);
                     }
                     return ScanToReturn.scan();
                 }).then(signatureJson => {
                     console.log(signatureJson);
                     const sig = Convert.hexToByteArray(Convert.jsonToObject(signatureJson).signature);
                     console.dir(sig);
                     return bar.registerClient(sig, signData)
                 }).then(() => {
                     return bar.addOrderToHistory(new Date(Date.now()));
                 })
                     .then(() => {
                         // Alert is shown in the modal page if not enclosed in setTimeout
                         setTimeout(() => {
                             Dialog.alert({
                                 title: "Success !",
                                 message: "The item is delivered !",
                                 okButtonText: "Great"
                             })
                         });
                     }).catch(error => {
                     if (error === USER_CANCELED) {
                         return Promise.resolve();
                     }
                     console.log(error);
                     console.dir(error);
                     console.trace();

                     // Alert is shown in the modal page if not enclosed in setTimeout
                     setTimeout(() => {
                         Dialog.alert({
                             title: "Error",
                             message: error,
                             okButtonText: "Ok"
                         });
                     });

                     return Promise.reject(error);
                 });

        }, true);

      } else if (result === "Show orders history") {
        Frame.topmost().navigate({
          moduleName: "drawers/pop/bar/order-history/bar-history-list",
          context: {
            bar: bar,
          }
        });

      } else if (result === "Delete Service"){
          bar.remove()
              .then(() => {
                  const listView = Frame.topmost().currentPage.getViewById("listView");
                  listView.notifySwipeToExecuteFinished();

                  return loadBars();
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

    })

}


function deleteBar(args) {
  console.dir(args.object.bindingContext);
  const bar = args.object.bindingContext.bar;
  bar.remove()
    .then(() => {
      const listView = Frame.topmost().currentPage.getViewById("listView");
      listView.notifySwipeToExecuteFinished();

      return loadBars();
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

  swipeLimits.right = width;
  swipeLimits.threshold = width / 2;
}

function addBar() {
  if (PoP.getFinalStatements().length === 0) {
    return Dialog.alert({
      title: "No group available",
      message: "You didn't participate to any party. Please do so to have a group to which you can get items !",
      okButtonText: "Ok"
    });

  }

  Frame.topmost().navigate({
    moduleName: "drawers/pop/bar/config/bar-config",
  });


}

function onDrawerButtonTap(args) {
  const sideDrawer = Frame.topmost().getViewById("sideDrawer");
  sideDrawer.showDrawer();
}

module.exports.onLoaded = onLoaded;
module.exports.partyTapped = barTapped;
module.exports.onSwipeCellStarted = onSwipeCellStarted;
module.exports.deleteBar = deleteBar;
module.exports.addBar = addBar;
module.exports.onNavigatingTo = onNavigatingTo;
module.exports.onDrawerButtonTap = onDrawerButtonTap;
module.exports.barTapped = barTapped;
