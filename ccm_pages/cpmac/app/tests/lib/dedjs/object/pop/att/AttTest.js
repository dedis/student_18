const ChaiAsPromised = require("chai-as-promised");
chai.use(ChaiAsPromised);
chai.should();

const FilesPath = require("../../../../../../shared/res/files/files-path");
const FileIO = require("../../../../../../shared/lib/file-io/file-io");

const AttParty = require("../../../../../../shared/lib/dedjs/object/pop/att/AttParty").get;

describe("AttParty", function () {

  function clean() {
    const promises = Object.getOwnPropertyNames(FilesPath).map(filePath => {
      return FileIO.writeStringTo(filePath, "");
    });

    //promises.push(AttParty.reset());

    return Promise.all(promises)
      .catch(error => {
        console.log(error);
        console.dir(error);
        console.trace();

        return Promise.reject(error);
      });
  }

  before("Clean Files Before Starting", function () {
    return clean();
  });

  after("Clean Files After Testing", function () {
    return clean();
  });

  beforeEach("Clean Files Before Each Test", function () {
    return clean();
  });

  afterEach("Clean Files After Each Test", function () {
    return clean();
  });

  it("should be a singleton", function () {
    const Att2 = require("../../../../../../shared/lib/dedjs/object/pop/att/AttParty").get;

    (Att2 === AttParty).should.be.true;
  });
});
