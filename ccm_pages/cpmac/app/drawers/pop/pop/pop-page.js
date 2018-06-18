const ObservableModule = require("data/observable");
const ObservableArray = require("data/observable-array").ObservableArray;
const Dialog = require("ui/dialogs");
const HashJs = require("hash.js");
const Convert = require("../../../shared/lib/dedjs/Convert");
const ScanToReturn = require("../../../shared/lib/scan-to-return/scan-to-return");
const User = require("../../../shared/lib/dedjs/object/user/User").get;
const PoP = require("../../../shared/lib/dedjs/object/pop/PoP").get;
const Org = require("../../../shared/lib/dedjs/object/pop/org/OrgParty").Party;

const FINAL_STATEMENT_OPTION_DELETE = "Delete";
const FINAL_STATEMENT_OPTION_QR = "QR";
const FINAL_STATEMENT_OPTION_POP_TOKENIFY = "PoP-Tokenify";

const POP_TOKEN_OPTION_REVOKE = "Revoke";
const POP_TOKEN_OPTION_SIGN = "Sign";

let pageObject = undefined;

const viewModel = ObservableModule.fromObject({
  finalStatements: PoP.getFinalStatements(),
  popToken: PoP.getPopToken(),
  isPopTokenEmpty: true,
});

function onLoaded(args) {
  const page = args.object;
  pageObject = page.parent.page;
  page.bindingContext = viewModel;

  // Bind isPopTokenEmpty to PopToken array length
  viewModel.isPopTokenEmpty = viewModel.popToken.length === 0;
  viewModel.popToken.on(ObservableArray.changeEvent, () => {
    viewModel.set('isPopTokenEmpty', viewModel.popToken.length === 0);
  });

}

function finalStatementTapped(args) {
  return Dialog.action({
    message: "Choose an Action",
    cancelButtonText: "Cancel",
    actions: [FINAL_STATEMENT_OPTION_DELETE, FINAL_STATEMENT_OPTION_QR, FINAL_STATEMENT_OPTION_POP_TOKENIFY]
  })
    .then(result => {
      if (result === FINAL_STATEMENT_OPTION_DELETE) {
        // Delete Final Statement
        return PoP.deleteFinalStatementByIndex(args.index);
      } else if (result === FINAL_STATEMENT_OPTION_POP_TOKENIFY) {
        // PoP-Tokenify
        if (User.isKeyPairSet()) {
          return PoP.generatePopTokenByIndex(args.index);
        } else {
          return Dialog.alert({
            title: "Missing Key Pair",
            message: "Please set a key pair in your settings.",
            okButtonText: "Ok"
          });
        }
      } else if (result === FINAL_STATEMENT_OPTION_QR) {
        // Show QR of Final Statement

        const popDesc = PoP.getFinalStatements().getItem(args.index).desc;
        const descHash = Convert.hexToByteArray(HashJs.sha256()
          .update(popDesc.name)
          .update(popDesc.dateTime)
          .update(popDesc.location)
          .update(popDesc.roster.aggregate)
          .digest("hex"));

        if (Org.isLinkedConodeSet()) {
          const object = {};
          object.conode = Org.getLinkedConode();
          object.id = Convert.byteArrayToBase64(descHash);

          pageObject.showModal("shared/pages/qr-code/qr-code-page", {
            textToShow: Convert.objectToJson(object),
            title: "Final Statement"
          }, () => {
          }, true);

          return Promise.resolve();
        } else {
          return Dialog.alert({
            title: "Not Linked to Conode",
            message: "Please link to your conode first.",
            okButtonText: "Ok"
          });
        }
      }

      return Promise.resolve();
    })
    .catch(error => {
      console.log(error);
      console.dir(error);
      console.trace();

      Dialog.alert({
        title: "Error",
        message: "An error occured, please retry. - " + error,
        okButtonText: "Ok"
      });

      return Promise.reject(error);
    });
}

function popTokenTapped(args) {
  let index = args.index;
  return Dialog.action({
    message: "Choose an Action",
    cancelButtonText: "Cancel",
    actions: [POP_TOKEN_OPTION_REVOKE, POP_TOKEN_OPTION_SIGN]
  })
    .then(result => {
      if (result === POP_TOKEN_OPTION_REVOKE) {
        // Revoke Token
        return PoP.revokePopTokenByIndex(args.index);
      } else if (result === POP_TOKEN_OPTION_SIGN) {
        return ScanToReturn.scan()
          .then(signDataJson => {
            console.dir(signDataJson);
            const sigData = Convert.jsonToObject(signDataJson);
            const sig = PoP.signWithPopTokenIndex(index, Convert.hexToByteArray(sigData.nonce), Convert.hexToByteArray(sigData.scope));

            const fields = {
              signature: Convert.byteArrayToHex(sig)
            };


            pageObject.showModal("shared/pages/qr-code/qr-code-page", {
              textToShow: Convert.objectToJson(fields),
              title: "Signed informations"
            }, () => {
            }, true);

            return Promise.resolve()
          })
          .catch(error => {
            console.log(error);
            console.dir(error);
            console.trace();

            if (error !== ScanToReturn.SCAN_ABORTED) {
              setTimeout(() => {
                Dialog.alert({
                  title: "Error",
                  message: "An error occured, please retry. - " + error,
                  okButtonText: "Ok"
                });
              });
            }

          })
      }

      return Promise.resolve();
    })
    .catch(error => {
      console.log(error);
      console.dir(error);
      console.trace();

      Dialog.alert({
        title: "Error",
        message: "An error occured, please retry. - " + error,
        okButtonText: "Ok"
      });

      return Promise.reject(error);
    });
}

function scanFinalStatement() {
  return ScanToReturn.scan()
    .then(fetchConodeIdJson => {
      const object = Convert.jsonToObject(fetchConodeIdJson);
      const conode = Convert.parseJsonServerIdentity(Convert.objectToJson(object.conode));
      const id = Convert.base64ToByteArray(object.id);

      return PoP.fetchFinalStatement(conode, id);
    })
    .catch(error => {
      console.log(error);
      console.dir(error);
      console.trace();

      if (error !== ScanToReturn.SCAN_ABORTED) {
        setTimeout(() => {
          Dialog.alert({
            title: "Error",
            message: "An error occured, please retry. - " + error,
            okButtonText: "Ok"
          });
        });
      }

      return Promise.reject(error);
    });
}

module.exports.onLoaded = onLoaded;
module.exports.finalStatementTapped = finalStatementTapped;
module.exports.popTokenTapped = popTokenTapped;
module.exports.scanFinalStatement = scanFinalStatement;
