const Dialog = require("ui/dialogs");
const Frame = require("ui/frame");
const Helper = require("../../../../shared/lib/dedjs/Helper");
const Convert = require("../../../../shared/lib/dedjs/Convert");
const ObjectType = require("../../../../shared/lib/dedjs/ObjectType");
const ScanToReturn = require("../../../../shared/lib/scan-to-return/scan-to-return");
const Observable = require("tns-core-modules/data/observable");
const User = require("../../../../shared/lib/dedjs/object/user/User").get;
const PoP = require("../../../../shared/lib/dedjs/object/pop/PoP").get;
const Bar = require("../../../../shared/lib/dedjs/object/beercoin/Bar").Bar;
const BarFrequencies = require("../../../../shared/lib/dedjs/object/beercoin/Bar").Frequencies;
const topmost = require("ui/frame").topmost;


let pageObject = undefined;

let finalStatementsMap = PoP.getFinalStatements().map((statement, index) => {
  return {key: index, label: statement.desc.name};
});

let dataForm = Observable.fromObject({
  name: "",
  frequency: BarFrequencies.DAILY,
  final_statement: 0
});

let viewModel = Observable.fromObject({
  dataForm: dataForm,
  finalStatements: finalStatementsMap,
  frequencies: [
    {key: BarFrequencies.DAILY, label: "Daily"},
    {key: BarFrequencies.WEEKLY, label: "Weekly"},
    {key: BarFrequencies.MONTHLY, label: "Monthly"},
  ],
});

function onNavigatingTo(args) {
  if (args.isBackNavigation) {
    return;
  }

  const page = args.object;

  pageObject = page.page;
  page.bindingContext = viewModel;

}

function onSwipeCellStarted(args) {
  const swipeLimits = args.data.swipeLimits;
  const swipeView = args.object;

  const deleteButton = swipeView.getViewById("button-delete");

  const width = deleteButton.getMeasuredWidth();

  swipeLimits.right = width;
  swipeLimits.threshold = width / 2;
}

/**
 * Save the config back to the file
 */
function save() {
  Bar.createWithConfig(dataForm.name, dataForm.frequency, PoP.getFinalStatements().getItem(dataForm.final_statement))
    .then(() => {
      goBack();
      return Promise.resolve()
    })
    .catch(error => {
      console.log(error);
      console.dir(error);
      console.trace();

      Dialog.alert({
        title: "Error",
        message: error,
        okButtonText: "Ok"
      });

      return Promise.reject(error);
    });




}

function goBack() {
  topmost().goBack();
}

module.exports.onNavigatingTo = onNavigatingTo;
module.exports.onSwipeCellStarted = onSwipeCellStarted;
module.exports.goBack = goBack;
module.exports.save = save;
