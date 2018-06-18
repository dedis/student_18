const ChaiAsPromised = require("chai-as-promised");
chai.use(ChaiAsPromised);
chai.should();

require("nativescript-nodeify");
const Kyber = require("@dedis/kyber-js");
const CURVE_ED25519 = new Kyber.curve.edwards25519.Curve;

const Convert = require("../../../shared/lib/dedjs/Convert");
const Helper = require("../../../shared/lib/dedjs/Helper");
const ObjectType = require("../../../shared/lib/dedjs/ObjectType");

const Crypto = require("../../../shared/lib/dedjs/Crypto");


let POINTS = ["HkDzpR5Imd7WNx8kl2lJcIVRVn8gfDByJnmlfrYh/zU=", "Fx6zzvJM6VzxfByLY2+uArGPtd2lHKPVmoXGMhdaFCA=", "j53MMKZNdtLlglcK9Ct1YYtkbbEOfq3R8ZoJOFIu6tE="];
POINTS = POINTS.map(publicKey => {
  let point = CURVE_ED25519.point();
  point.unmarshalBinary(Convert.base64ToByteArray(publicKey));

  return point;
});
const POINTS_AGGREGATE = "q+G+7n6FXsY7hpxK3m119GuDHnchS6wqTE0sZE/fOKg=";
const POINTS_AGGREGATE_BYTE_ARRAY = Convert.base64ToByteArray(POINTS_AGGREGATE);


describe("Crypto", function () {
  describe("#aggregatePublicKeys", function () {
    it("should throw an error when the input is not an array", function () {
      expect(() => Crypto.aggregatePublicKeys("POINTS")).to.throw();
    });

    it("should throw an error when the input is an empty array", function () {
      expect(() => Crypto.aggregatePublicKeys([])).to.throw();
    });

    it("should throw an error when the input is not an array of points", function () {
      expect(() => Crypto.aggregatePublicKeys([1, 2, 3])).to.throw();
    });

    it("should correctly compute the aggregate of the points", function () {
      const aggregate = Crypto.aggregatePublicKeys(POINTS);

      aggregate.should.deep.equal(POINTS_AGGREGATE_BYTE_ARRAY);
    });
  });

  describe("#generateRandomKeyPair", function () {
    it("should return a KeyPair object and the keys should have the right length", function () {
      const keyPair = Crypto.generateRandomKeyPair();

      Helper.isOfType(keyPair, ObjectType.KEY_PAIR).should.be.true;

      //console.log(Convert.byteArrayToBase64(keyPair.public));
      //console.log(Convert.byteArrayToBase64(keyPair.private));
      //console.log(Convert.byteArrayToBase64(keyPair.publicComplete));
    });
  });
});
