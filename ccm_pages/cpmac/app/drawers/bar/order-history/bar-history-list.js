const Dialog = require("ui/dialogs");
const ObservableArray = require("data/observable-array").ObservableArray;
const topmost = require("ui/frame").topmost;
const Bar = require("../../../shared/lib/dedjs/object/beercoin/Bar").Bar;

let bar = undefined;

let viewModel = {
  dates: new ObservableArray()
};

function onLoaded(args) {
  const page = args.object;
  const context = page.navigationContext;

  page.bindingContext = viewModel;

  if (context.bar === undefined) {
    throw new Error("A bar should be given in the context");
  } else if (!(context.bar instanceof Bar)) {
    throw new Error("bar given in context should be an instance of Bar")
  }

  bar = context.bar;

  let countLabel = page.getViewById("count");
  // Without this the text is not vertically centered in is own view
  countLabel.android.setGravity(android.view.Gravity.CENTER);

  loadDates();
}

function loadDates() {
  viewModel.dates.splice(0);

  const orderHistory = bar.getOrderHistoryModule();
  orderHistory.forEach(date => {
    viewModel.dates.push({
      date: date.toString()
    })
  })
}

function goBack() {
  topmost().goBack();
}

function clear() {
  Dialog.confirm({
    title: "Be careful !",
    message: "Every orders in this history will be deleted ! Are you sure you want to continue ?",
    okButtonText: "Yes",
    cancelButtonText: "No"
  }).then(result => {
    if (result) {
      viewModel.dates.splice(0);
      return bar.resetOrderHistory();
    } else {
      return Promise.resolve()
    }
  });
}

module.exports.goBack = goBack;
module.exports.onLoaded = onLoaded;
module.exports.clear = clear;