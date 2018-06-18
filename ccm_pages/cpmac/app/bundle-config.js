if (global.TNS_WEBPACK) {
  // registers tns-core-modules UI framework modules
  require("bundle-entry-points");

  // register application modules
  global.registerModule("nativescript-ui-sidedrawer",
    () => require("../node_modules/nativescript-ui-sidedrawer"));

  global.registerModule("shared/my-drawer/MyDrawer", () => require("./shared/my-drawer/MyDrawer"));
  global.registerModule("home/home-page", () => require("./drawers/home/home-page"));
  global.registerModule("pop/pop-page", () => require("./drawers/pop/pop-page"));
  global.registerModule("cisc/cisc-page", () => require("./drawers/cisc/cisc-page"));
  global.registerModule("settings/settings-page", () => require("./drawers/settings/settings-page"));
}
