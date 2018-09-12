const Dialog = require("ui/dialogs");
const PoP = require("../../../shared/lib/dedjs/object/pop/PoP").get;
const Org = require("../../../shared/lib/dedjs/object/pop/org/OrgParty").Party;

function onLoaded(args) {
  const page = args.object;
}

function resetPop() {
  return Dialog.confirm({
    title: "ALERT",
    message: "You are about to completely reset the PoP service, this action can NOT be undone! Please confirm.",
    okButtonText: "Reset",
    cancelButtonText: "Cancel"
  })
    .then(result => {
      if (result) {
        return PoP.reset()
          .then(() => {
            return Dialog.alert({
              title: "PoP Has Been Reset",
              message: "Everything belonging to the PoP service has been completely reset.",
              okButtonText: "Ok"
            });
          });
      }

      return Promise.resolve();
    })
    .catch(error => {
      console.log(error);
      console.dir(error);
      console.trace();

      return Dialog.alert({
        title: "Error",
        message: "An unexpected error occurred. Please try again. - " + error,
        okButtonText: "Ok"
      });

      return Promise.reject(error);
    });
}

function resetOrganizer() {
  return Dialog.confirm({
    title: "ALERT",
    message: "You are about to completely reset the organizer, this action can NOT be undone! Please confirm.",
    okButtonText: "Reset",
    cancelButtonText: "Cancel"
  })
    .then(result => {
      if (result) {
        return Org.reset()
          .then(() => {
            return Dialog.alert({
              title: "Organizer Has Been Reset",
              message: "Everything belonging to the organizer has been completely reset.",
              okButtonText: "Ok"
            });
          });
      }

      return Promise.resolve();
    })
    .catch(error => {
      console.log(error);
      console.dir(error);
      console.trace();

      return Dialog.alert({
        title: "Error",
        message: "An unexpected error occurred. Please try again. - " + error,
        okButtonText: "Ok"
      });

      return Promise.reject(error);
    });
}

module.exports.onLoaded = onLoaded;
module.exports.resetPop = resetPop;
module.exports.resetOrganizer = resetOrganizer;
