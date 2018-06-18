const ChaiAsPromised = require("chai-as-promised");
chai.use(ChaiAsPromised);
chai.should();

const FileIO = require("../../../shared/lib/file-io/file-io");

describe("FileIO", function () {
  describe("#getStringOf", function () {
    it("should throw when filePath is not a string", function () {
      expect(() => FileIO.getStringOf(42)).to.throw();
    });
  });

  describe("#writeStringTo", function () {
    it("should throw when filePath is not a string", function () {
      expect(() => FileIO.writeStringTo(42, "Write this.")).to.throw();
    });

    it("should throw when string is not a string", function () {
      expect(() => FileIO.writeStringTo("path/to/file.txt", 42)).to.throw();
    });
  });
});
