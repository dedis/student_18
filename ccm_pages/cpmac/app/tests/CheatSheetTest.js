const ChaiAsPromised = require("chai-as-promised");
chai.use(ChaiAsPromised);
chai.should();

describe("Module", function () {
  describe("#Function", function () {
    before("Optional Description", function () {
      // Prepare stuff before all the tests.
    });

    after("Optional Description", function () {
      // Clean up after all the tests.
    });

    beforeEach("Optional Description", function () {
      // Do stuff before each test.
    });

    afterEach("Optional Description", function () {
      // Do stuff after each test.
    });

    it("should ...", function () {
      [1, 2, 3].indexOf(4).should.equal(-1);
    });

    it("should ...", function () {
      return Promise.resolve(2 + 2).should.eventually.equal(4);
    });

    it("should throw ...", function () {
      expect(() => {
        throw new Error()
      }
      ).to.throw();
    });
  });
});

/*
should.exist
should.not.exist
should.equal
should.not.equal
should.Throw
should.not.Throw
foo.should.equal("bar");
foo.should.have.lengthOf(3);
tea.should.have.property("lavors").with.lengthOf(3);

return promise.should.be.fulfilled;
return promise.should.eventually.deep.equal("foo");
return promise.should.become("foo"); // same as ".eventually.deep.equal"
return promise.should.be.rejected;
return promise.should.be.rejectedWith(Error); // other variants of Chai's "throw" assertion work too.
*/
