const Frame = require("ui/frame");

function onNavigatingTo(args) {
  const page = args.object;
}

function onDrawerButtonTap(args) {
  const sideDrawer = Frame.topmost().getViewById("sideDrawer");
  sideDrawer.showDrawer();
}

module.exports.onNavigatingTo = onNavigatingTo;
module.exports.onDrawerButtonTap = onDrawerButtonTap;
