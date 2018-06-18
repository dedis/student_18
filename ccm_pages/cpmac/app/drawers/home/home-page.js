const Frame = require("ui/frame");
const Dialog = require("ui/dialogs");
const Helper = require("../../shared/lib/dedjs/Helper");
const Convert = require("../../shared/lib/dedjs/Convert");
const ObjectType = require("../../shared/lib/dedjs/ObjectType");
const CothorityMessages = require("../../shared/lib/dedjs/network/cothority-messages");
const ScanToReturn = require("../../shared/lib/scan-to-return/scan-to-return");
const User = require("../../shared/lib/dedjs/object/user/User").get;
const ObservableModule = require("data/observable");
const ObservableArray = require("data/observable-array").ObservableArray;
const Timer = require("timer");

const viewModel = ObservableModule.fromObject({
  rosterModule: User.getRosterModule(),
  isRosterEmpty: true
});

let pageObject = undefined;
let timerId = undefined;

function onLoaded() {
  // Poll the statuses every 2s
  timerId = Timer.setInterval(() => {
    loadConodeList();
  }, 2000)

}

function onUnloaded() {
  // remove polling when page is leaved
  Timer.clearInterval(timerId);
}

function onNavigatingTo(args) {
  const page = args.object;
  pageObject = page.page;
  page.bindingContext = viewModel;

  // Bind isEmpty to the length of the array
  viewModel.isRosterEmpty = viewModel.rosterModule.list.length === 0;
  viewModel.rosterModule.list.on(ObservableArray.changeEvent, () => {
    viewModel.set('isRosterEmpty', viewModel.rosterModule.list.length === 0);
  });

  if (viewModel.rosterModule.statusList.length !== viewModel.rosterModule.list.length) {
    loadConodeList();
  }
}

function loadConodeList() {
  if (viewModel.rosterModule.isLoading) {
    return Promise.resolve();
  }
  return User.getRosterStatus();
}

function deblockConodeList() {
  Frame.topmost().navigate({
    clearHistory: true,
    moduleName: "drawers/home/home-page",
    transition: {
      name: "fade",
      duration: 0
    }
  });
}

function conodeTapped(args) {
  const index = args.index;
  const conodesId = Convert.byteArrayToBase64(User.getRoster().list[index].id);
  let conodeAndStatusPair = undefined;
  User._roster.statusList.slice().forEach(object => {
    if (Convert.byteArrayToBase64(object.conode.id) === conodesId) {
      conodeAndStatusPair = object;
    }
  });

  if (conodeAndStatusPair !== undefined) {
    Frame.topmost().navigate({
      moduleName: "drawers/home/conode-stats/conode-stats-page",
      bindingContext: conodeAndStatusPair
    });
  } else {
    return Dialog.alert({
      title: "No Status for this Conode",
      message: "Please check your conodes information and try to reload.",
      okButtonText: "Ok"
    });
  }
}

function addConode() {
  function addManualCallBack(server) {
    if (server !== undefined && !Helper.isOfType(server, ObjectType.SERVER_IDENTITY)) {
      throw new Error("server must be an instance of ServerIdentity or undefined to be skipped");
    }

    if (server !== undefined) {
      return User.addServer(server)
        .then(() => {
          return loadConodeList();
        })
        .catch(error => {
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
  }

  return Dialog.confirm({
    title: "Choose a Method",
    message: "How do you want to add the conode?",
    okButtonText: "Scan QR",
    cancelButtonText: "Cancel",
    neutralButtonText: "Manual"
  })
    .then(result => {
      if (result) {
        // Scan
        return ScanToReturn.scan()
          .then(string => {
            let conode = undefined;

            try {
              conode = Convert.parseJsonServerIdentity(string);
            } catch (error) { }

            if (conode === undefined) {
              try {
                conode = Convert.parseTomlRoster(string).list[0];
              } catch (error) { }
            }

            if (conode === undefined) {
              return Promise.reject("parsing error");
            }

            return User.addServer(conode);
          });
      } else if (result === undefined) {
        pageObject.showModal("shared/pages/add-conode-manual/add-conode-manual", undefined, addManualCallBack, true);
        return Promise.resolve();
      } else {
        // Cancel
        return Promise.resolve();
      }
    })
    .catch(error => {
      console.log(error);
      console.dir(error);
      console.trace();

      if (error !== ScanToReturn.SCAN_ABORTED) {
        setTimeout(() => {
          Dialog.alert({
            title: "Error",
            message: "An error occured, please check the code you scanned. - " + error,
            okButtonText: "Ok"
          });
        });
      }

      return Promise.reject(error);
    });
}

function deleteConode(args) {
  // We do not get the index of the item swiped/clicked...
  const conode = args.object.bindingContext;

  return User.substractRoster(CothorityMessages.createRoster(undefined, [conode], conode.public))
    .then(() => {
      const listView = Frame.topmost().currentPage.getViewById("listView");
      listView.notifySwipeToExecuteFinished();

      return Promise.resolve();
    })
    .catch(error => {
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

function onDrawerButtonTap(args) {
  const sideDrawer = Frame.topmost().getViewById("sideDrawer");
  sideDrawer.showDrawer();
}

module.exports.onNavigatingTo = onNavigatingTo;
module.exports.onDrawerButtonTap = onDrawerButtonTap;
module.exports.onSwipeCellStarted = onSwipeCellStarted;
module.exports.loadConodeList = loadConodeList;
module.exports.deblockConodeList = deblockConodeList;
module.exports.conodeTapped = conodeTapped;
module.exports.addConode = addConode;
module.exports.deleteConode = deleteConode;
module.exports.onLoaded = onLoaded;
module.exports.onUnloaded = onUnloaded;
