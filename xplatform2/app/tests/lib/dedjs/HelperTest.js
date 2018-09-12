const ChaiAsPromised = require("chai-as-promised");
chai.use(ChaiAsPromised);
chai.should();

const Convert = require("../../../shared/lib/dedjs/Convert");

const Helper = require("../../../shared/lib/dedjs/Helper");

const PUBLIC_KEY = "y4JMDWrle6RMV+0BKU92Xbu8+J8VkZ5kV3SvSr2ZxHw=";
const PUBLIC_KEY_BYTE_ARRAY = Convert.base64ToByteArray(PUBLIC_KEY);
const PUBLIC_KEY_INCORRECT = "a4JMDWrle6RMV+0BKU92Xbu8+J8VkZ5kV3SvSr2ZxHw=";
const PUBLIC_KEY_INCORRECT_BYTE_ARRAY = Convert.base64ToByteArray(PUBLIC_KEY_INCORRECT);

const COMPLEX_OBJECT = {
  a: {
    a: [1, "2", 3, "4"],
    b: {
      c: 3
    }
  },
  b: {
    a: {
      c: 4
    },
    b: ["2", 2, "1", 1]
  }
};

describe("Helper", function () {
  describe("#isOfType", function () {
    it("should throw an error when type is not a string", function () {
      expect(() => Helper.isOfType({}, PUBLIC_KEY_BYTE_ARRAY)).to.throw();
    });

    it("should correctly find that a string is not a type of object", function () {
      const bool = Helper.isOfType("{}", "Object");

      bool.should.be.false;
    });

    it("should correctly find that undefined is not any type of object", function () {
      const bool = Helper.isOfType(undefined, "Object");

      bool.should.be.false;
    });

    it("should correctly check the type of a simple object", function () {
      const bool = Helper.isOfType({}, "Object");

      bool.should.be.true;
    });

    it("should correctly check the type of a random object", function () {
      const bool = Helper.isOfType(new Uint8Array(), "Uint8Array");

      bool.should.be.true;
    });
  });

  describe("#isArray", function () {
    it("should throw an error when object is undefined", function () {
      expect(() => Helper.isArray(undefined)).to.throw();
    });

    it("should throw an error when object is not an object", function () {
      expect(() => Helper.isArray("[]")).to.throw();
    });

    it("should correctly check that a pure object is not an array", function () {
      const bool = Helper.isArray({});

      bool.should.be.false;
    });

    it("should correctly check the type of a simple array", function () {
      const bool = Helper.isArray(new Array());

      bool.should.be.true;
    });

    it("should correctly check the type of a random array", function () {
      const bool = Helper.isArray(new Uint8Array());

      bool.should.be.true;
    });
  });

  describe("#isValidPublicKey", function () {
    it("should throw an error when publicKey is not a byte array", function () {
      expect(() => Helper.isValidPublicKey("PUBLIC_KEY_BYTE_ARRAY")).to.throw();
    });

    it("should correctly check that a key is not long enough", function () {
      const bool = Helper.isValidPublicKey(new Uint8Array([0, 1, 2, 3]));

      bool.should.be.false;
    });

    it("should correctly check that a key is correct", function () {
      const bool = Helper.isValidPublicKey(PUBLIC_KEY_BYTE_ARRAY);

      bool.should.be.true;
    });

    it("should correctly check a right length key could not be correct", function () {
      const bool = Helper.isValidPublicKey(PUBLIC_KEY_INCORRECT_BYTE_ARRAY);

      bool.should.be.false;
    });
  });

  describe("#isValidAddress", function () {
    it("should throw an error when address is not a string", function () {
      expect(() => Helper.isValidAddress(PUBLIC_KEY_BYTE_ARRAY)).to.throw();
    });

    it("should correctly check that an address is correct", function () {
      let bool = Helper.isValidAddress("tls://10.0.2.2:7002");
      bool.should.be.true;

      bool = Helper.isValidAddress("tls://10.0.2.2:65534");
      bool.should.be.true;

      bool = Helper.isValidAddress("tls://10.0.2.2:0");
      bool.should.be.true;
    });

    it("should correctly check that an address is incorrect", function () {
      let bool = Helper.isValidAddress("tls://10,0.2.2:7002");
      bool.should.be.false;

      bool = Helper.isValidAddress("tls://10.0.2.2,7002");
      bool.should.be.false;

      bool = Helper.isValidAddress("tls:/10.0.2.2:7002");
      bool.should.be.false;

      bool = Helper.isValidAddress("tls:://10.0.2.2:7002");
      bool.should.be.false;

      bool = Helper.isValidAddress("tc://10.0.2.2:7002");
      bool.should.be.false;

      bool = Helper.isValidAddress("ws://10.0.2.2:7002");
      bool.should.be.false;

      bool = Helper.isValidAddress("tls://10.0.2.2:-3");
      bool.should.be.false;

      bool = Helper.isValidAddress("tls://10.0.2.2:65535");
      bool.should.be.false;

      bool = Helper.isValidAddress("tls://256.0.2.2:7002");
      bool.should.be.false;

      bool = Helper.isValidAddress("tls://10.0.-2.2:7002");
      bool.should.be.false;
    });
  });

  describe("#deepCopy", function () {
    it("should throw an error when object is not an object", function () {
      expect(() => Helper.deepCopy("COMPLEX_OBJECT")).to.throw();
    });

    it("should correctly deep copy a complex object", function () {
      const deepCopy = Helper.deepCopy(COMPLEX_OBJECT);

      deepCopy.should.deep.equal(COMPLEX_OBJECT);
    });
  });
});
