const ChaiAsPromised = require("chai-as-promised");
chai.use(ChaiAsPromised);
chai.should();

require("nativescript-nodeify");
const Kyber = require("@dedis/kyber-js");
const CURVE_ED25519 = new Kyber.curve.edwards25519.Curve;

const FilesPath = require("../../../../../shared/res/files/files-path");
const FileIO = require("../../../../../shared/lib/file-io/file-io");
const Convert = require("../../../../../shared/lib/dedjs/Convert");
const Helper = require("../../../../../shared/lib/dedjs/Helper");
const ObjectType = require("../../../../../shared/lib/dedjs/ObjectType");
const Crypto = require("../../../../../shared/lib/dedjs/Crypto");
const CothorityMessages = require("../../../../../shared/lib/dedjs/network/cothority-messages");

const User = require("../../../../../shared/lib/dedjs/object/user/User").get;

const PRIVATE_KEY = "AWKlOlcTuCHEV/fKX0X1IoAoBU0n1c5iKp/SWRLj3T4=";
const PRIVATE_KEY_BYTE_ARRAY = Convert.base64ToByteArray(PRIVATE_KEY);
const PUBLIC_KEY = "y4JMDWrle6RMV+0BKU92Xbu8+J8VkZ5kV3SvSr2ZxHw=";
const PUBLIC_KEY_BYTE_ARRAY = Convert.base64ToByteArray(PUBLIC_KEY);
const PUBLIC_COMPLETE_KEY = "BBmiuL/uxUuItsuFVQJT4oUv4qZrb1fYQ+GL/ZTpZ43MfMSZvUqvdFdknpEVn/i8u112TykB7VdMpHvlag1Mgss=";
const PUBLIC_COMPLETE_KEY_BYTE_ARRAY = Convert.base64ToByteArray(PUBLIC_COMPLETE_KEY);
const JSON_KEY_PAIR = JSON.stringify({
  "private": PRIVATE_KEY,
  "public": PUBLIC_KEY,
  "publicComplete": PUBLIC_COMPLETE_KEY
});
const KEY_PAIR = Convert.parseJsonKeyPair(JSON_KEY_PAIR);

const ROSTER_ID = "8yc0TaIweWRyMA==";
const ROSTER_ID_BYTE_ARRAY = Convert.base64ToByteArray(ROSTER_ID);
const ROSTER_LIST = [
  {
    "public": "HkDzpR5Imd7WNx8kl2lJcIVRVn8gfDByJnmlfrYh/zU=",
    "id": "z6kCTQ77Xna9yfgKka5lNQ==",
    "address": "tls://10.0.2.2:7002",
    "description": "Conode_1"
  },
  {
    "public": "Fx6zzvJM6VzxfByLY2+uArGPtd2lHKPVmoXGMhdaFCA=",
    "id": "Qd8XkrUlVEeClO9I95nklQ==",
    "address": "tls://10.0.2.2:7004",
    "description": "Conode_2"
  },
  {
    "public": "j53MMKZNdtLlglcK9Ct1YYtkbbEOfq3R8ZoJOFIu6tE=",
    "id": "tUq+0651WRaAI4aTQC0d8w==",
    "address": "tls://10.0.2.2:7006",
    "description": "Conode_3"
  }
];
const ROSTER_LIST_BYTE_ARRAY = ROSTER_LIST.map(conode => {
  const copy = Helper.deepCopy(conode);
  copy.public = Convert.base64ToByteArray(conode.public);
  copy.id = Convert.base64ToByteArray(conode.id);

  return copy;
});
const ROSTER_AGGREGATE = "q+G+7n6FXsY7hpxK3m119GuDHnchS6wqTE0sZE/fOKg=";
const ROSTER_AGGREGATE_BYTE_ARRAY = Convert.base64ToByteArray(ROSTER_AGGREGATE);
const JSON_ROSTER_FULL = JSON.stringify({
  "id": ROSTER_ID,
  "list": ROSTER_LIST,
  "aggregate": ROSTER_AGGREGATE
});
const ROSTER = Convert.parseJsonRoster(JSON_ROSTER_FULL);

const EMPTY_ROSTER = CothorityMessages.createRoster(new Uint8Array(), [], new Uint8Array());

const ROSTER_ID_2 = "uSERdsRIbdyO6R==";
const ROSTER_ID_BYTE_ARRAY_2 = Convert.base64ToByteArray(ROSTER_ID_2);
const ROSTER_LIST_2 = [
  {
    "public": "vRcQ4GmyxC34Ag3ZAyiI5CyXy5pkfgFZe2GJpbQB/zU=",
    "id": "M0YVKeOx0nsKHQoFKPtYNQ==",
    "address": "tls://10.0.2.2:7008",
    "description": "Conode_4"
  },
  {
    "public": "4NWGV7hzH4LDGUhCOQSX2qBCb40lDPIGQ4vWMZIkFCA=",
    "id": "NOxPV4jduFBBsKLZqb1alQ==",
    "address": "tls://10.0.2.2:7010",
    "description": "Conode_5"
  },
  {
    "public": "HkDzpR5Imd7WNx8kl2lJcIVRVn8gfDByJnmlfrYh/zU=",
    "id": "z6kCTQ77Xna9yfgKka5lNQ==",
    "address": "tls://10.0.2.2:7002",
    "description": "Conode_1"
  },
  {
    "public": "sDKFYWFa8R55ZSuiOT012qBCb40lDPIGQ4vWMZIk6tE=",
    "id": "i3ZiWNQo3r8wYEOLV9qh8w==",
    "address": "tls://10.0.2.2:7012",
    "description": "Conode_6"
  }
];
const ROSTER_LIST_BYTE_ARRAY_2 = ROSTER_LIST_2.map(conode => {
  const copy = Helper.deepCopy(conode);
  copy.public = Convert.base64ToByteArray(conode.public);
  copy.id = Convert.base64ToByteArray(conode.id);

  return copy;
});
const ROSTER_AGGREGATE_2 = "WssSrxrQFth7H9sGYfj3xyTk79SeSuvKJ8RZ1wqdOKg=";
const ROSTER_AGGREGATE_BYTE_ARRAY_2 = Convert.base64ToByteArray(ROSTER_AGGREGATE_2);
const JSON_ROSTER_FULL_2 = JSON.stringify({
  "id": ROSTER_ID_2,
  "list": ROSTER_LIST_2,
  "aggregate": ROSTER_AGGREGATE_2
});
const ROSTER_2 = Convert.parseJsonRoster(JSON_ROSTER_FULL_2);

const AGGREGATE_BOTH_ROSTER = (function fun() {
  const aggregate = [];

  ROSTER_LIST.forEach(server => {
    aggregate.push(server.public);
  });

  ROSTER_LIST_2.forEach(server => {
    if (!aggregate.includes(server.public)) {
      aggregate.push(server.public);
    }
  });

  return Crypto.aggregatePublicKeys(aggregate.map(publicKey => {
    let point = CURVE_ED25519.point();
    point.unmarshalBinary(Convert.base64ToByteArray(publicKey));

    return point;
  }));
})();

const CONODE_ADDRESS = "tls://10.0.2.2:7012";
const CONODE_PUBLIC_KEY = "sDKFYWFa8R55ZSuiOT012qBCb40lDPIGQ4vWMZIk6tE=";
const CONODE_PUBLIC_KEY_BYTE_ARRAY = Convert.base64ToByteArray(CONODE_PUBLIC_KEY);
const CONODE_DESCRIPTION = "Conode_6";
const CONODE_ID_REAL = "i3ZiWNQo3r8wYEOLV9qh8w==";
const CONODE_ID_REAL_BYTE_ARRAY = Convert.base64ToByteArray(CONODE_ID_REAL);
const SERVER_IDENTITY = Convert.toServerIdentity(CONODE_ADDRESS, CONODE_PUBLIC_KEY_BYTE_ARRAY, CONODE_DESCRIPTION, CONODE_ID_REAL_BYTE_ARRAY);

describe("User", function () {

  function clean() {
    const promises = Object.getOwnPropertyNames(FilesPath).map(filePath => {
      return FileIO.writeStringTo(filePath, "");
    });

    promises.push(User.reset());

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
    const User2 = require("../../../../../shared/lib/dedjs/object/user/User").get;

    (User2 === User).should.be.true;
  });

  it("should correctly load empty key pair", function () {
    const keyPair = User.getKeyPair();

    keyPair.private.should.be.empty;
    keyPair.public.should.be.empty;
    keyPair.publicComplete.should.be.empty;
  });

  it("should correctly load empty roster", function () {
    const roster = User.getRoster();

    roster.id.should.be.empty;
    roster.list.should.be.empty;
    roster.aggregate.should.be.empty;
  });

  it("should correctly load key pair", function () {
    return FileIO.writeStringTo(FileIO.join(FilesPath.USER_PATH, FilesPath.KEY_PAIR), JSON_KEY_PAIR)
      .then(() => {
        return User.load();
      })
      .then(() => {
        const keyPair = User.getKeyPair();

        keyPair.private.should.deep.equal(PRIVATE_KEY_BYTE_ARRAY);
        keyPair.public.should.deep.equal(PUBLIC_KEY_BYTE_ARRAY);
        keyPair.publicComplete.should.deep.equal(PUBLIC_COMPLETE_KEY_BYTE_ARRAY);
      });
  });

  it("should correctly load roster", function () {
    return FileIO.writeStringTo(FilesPath.ROSTER, JSON_ROSTER_FULL)
      .then(() => {
        return User.load();
      })
      .then(() => {
        const roster = User.getRoster();

        roster.id.should.deep.equal(ROSTER_ID_BYTE_ARRAY);
        roster.list.length.should.equal(ROSTER_LIST.length);
        for (let i = 0; i < ROSTER_LIST.length; ++i) {
          roster.list[i].public.should.deep.equal(ROSTER_LIST_BYTE_ARRAY[i].public);
          roster.list[i].id.should.deep.equal(ROSTER_LIST_BYTE_ARRAY[i].id);
          roster.list[i].address.should.equal(ROSTER_LIST_BYTE_ARRAY[i].address);
          roster.list[i].description.should.equal(ROSTER_LIST_BYTE_ARRAY[i].description);
        }
        roster.aggregate.should.deep.equal(ROSTER_AGGREGATE_BYTE_ARRAY);
      });
  });

  it("should correctly reset files and memory", function () {
    return FileIO.writeStringTo(FileIO.join(FilesPath.USER_PATH, FilesPath.KEY_PAIR), JSON_KEY_PAIR)
      .then(() => {
        return FileIO.writeStringTo(FilesPath.ROSTER, JSON_ROSTER_FULL);
      })
      .then(() => {
        return User.load()
          .then(() => {
            return User.reset()
          });
      })
      .then(() => {
        return FileIO.getStringOf(FileIO.join(FilesPath.USER_PATH, FilesPath.KEY_PAIR))
          .then(string => {
            string.should.be.empty;

            return FileIO.getStringOf(FilesPath.ROSTER)
              .then(string => {
                string.should.be.empty;

                return Promise.resolve();
              });
          });
      })
      .then(() => {
        const keyPair = User.getKeyPair();
        keyPair.private.should.be.empty;
        keyPair.public.should.be.empty;
        keyPair.publicComplete.should.be.empty;

        const roster = User.getRoster();
        roster.id.should.be.empty;
        roster.list.should.be.empty;
        roster.aggregate.should.be.empty;

        return Promise.resolve();
      });
  });

  describe("#emptyRosterStatusList", function () {
    it("should completely empty the status list", function () {
      for (let i = 0; i < 100; ++i) {
        User._roster.statusList.push(i);
      }

      User.emptyRosterStatusList();

      User._roster.statusList.length.should.be.equal(0);
    });
  });

  describe("#addRoster", function () {
    it("should throw an error when the input is not a roster", function () {
      expect(() => User.addRoster("ROSTER")).to.throw();
    });

    it("should correctly add an empty roster", function () {
      return User.setRoster(ROSTER, true)
        .then(() => {
          return User.addRoster(EMPTY_ROSTER);
        })
        .then(() => {
          const roster = User.getRoster();

          roster.id.should.deep.equal(ROSTER_ID_BYTE_ARRAY);
          roster.list.length.should.equal(ROSTER_LIST.length);
          for (let i = 0; i < ROSTER_LIST.length; ++i) {
            roster.list[i].public.should.deep.equal(ROSTER_LIST_BYTE_ARRAY[i].public);
            roster.list[i].id.should.deep.equal(ROSTER_LIST_BYTE_ARRAY[i].id);
            roster.list[i].address.should.equal(ROSTER_LIST_BYTE_ARRAY[i].address);
            roster.list[i].description.should.equal(ROSTER_LIST_BYTE_ARRAY[i].description);
          }
          roster.aggregate.should.deep.equal(ROSTER_AGGREGATE_BYTE_ARRAY);
        });
    });

    it("should correctly add an non-empty roster when previous was empty", function () {
      return User.addRoster(ROSTER)
        .then(() => {
          const roster = User.getRoster();

          roster.id.should.deep.equal(ROSTER_ID_BYTE_ARRAY);
          roster.list.length.should.equal(ROSTER_LIST.length);
          for (let i = 0; i < ROSTER_LIST.length; ++i) {
            roster.list[i].public.should.deep.equal(ROSTER_LIST_BYTE_ARRAY[i].public);
            roster.list[i].id.should.deep.equal(ROSTER_LIST_BYTE_ARRAY[i].id);
            roster.list[i].address.should.equal(ROSTER_LIST_BYTE_ARRAY[i].address);
            roster.list[i].description.should.equal(ROSTER_LIST_BYTE_ARRAY[i].description);
          }
          roster.aggregate.should.deep.equal(ROSTER_AGGREGATE_BYTE_ARRAY);
        });
    });

    it("should correctly add a non-empty roster (and handle duplicates)", function () {
      return User.setRoster(ROSTER, true)
        .then(() => {
          return User.addRoster(ROSTER_2);
        })
        .then(() => {
          const roster = User.getRoster();

          roster.id.should.be.empty;
          roster.list.length.should.equal(ROSTER.list.length + ROSTER_2.list.length - 1);
          roster.aggregate.should.deep.equal(AGGREGATE_BOTH_ROSTER);
        });
    });
  });

  describe("#addServer", function () {
    it("should throw an error when the input is not a server identity", function () {
      expect(() => User.addServer("SERVER_IDENTITY")).to.throw();
    });

    it("should correctly add a server to an empty roster", function () {
      return User.addServer(SERVER_IDENTITY)
        .then(() => {
          const roster = User.getRoster();

          roster.id.should.be.empty;
          roster.list.length.should.equal(1);
          roster.aggregate.should.deep.equal(SERVER_IDENTITY.public);
        });
    });

    it("should correctly add a server to a non empty roster", function () {
      return User.addRoster(ROSTER)
        .then(() => {
          return User.addServer(SERVER_IDENTITY)
        })
        .then(() => {
          const roster = User.getRoster();

          roster.id.should.be.empty;
          roster.list.length.should.equal(ROSTER.list.length + 1);

          let aggregatePoint = CURVE_ED25519.point();
          let publicPoint = CURVE_ED25519.point();

          aggregatePoint.unmarshalBinary(ROSTER.aggregate);
          publicPoint.unmarshalBinary(SERVER_IDENTITY.public);

          const aggregate = Crypto.aggregatePublicKeys([aggregatePoint, publicPoint]);
          roster.aggregate.should.deep.equal(aggregate);
        });
    });
  });

  describe("#addServerByInfo", function () {
    it("should throw an error when address is not a string", function () {
      expect(() => User.addServerByInfo(42, CONODE_PUBLIC_KEY_BYTE_ARRAY, CONODE_DESCRIPTION)).to.throw();
    });

    it("should throw an error when publicKey is not a byte array", function () {
      expect(() => User.addServerByInfo(CONODE_ADDRESS, "CONODE_PUBLIC_KEY_BYTE_ARRAY", CONODE_DESCRIPTION)).to.throw();
    });

    it("should throw an error when description is not a string", function () {
      expect(() => User.addServerByInfo(CONODE_ADDRESS, CONODE_PUBLIC_KEY_BYTE_ARRAY, 42)).to.throw();
    });

    it("should correctly add a server to an empty roster", function () {
      return User.addServerByInfo(CONODE_ADDRESS, CONODE_PUBLIC_KEY_BYTE_ARRAY, CONODE_DESCRIPTION)
        .then(() => {
          const roster = User.getRoster();

          roster.id.should.be.empty;
          roster.list.length.should.equal(1);
          roster.aggregate.should.deep.equal(CONODE_PUBLIC_KEY_BYTE_ARRAY);
        });
    });

    it("should correctly add a server to a non empty roster", function () {
      return User.addRoster(ROSTER)
        .then(() => {
          return User.addServerByInfo(CONODE_ADDRESS, CONODE_PUBLIC_KEY_BYTE_ARRAY, CONODE_DESCRIPTION)
        })
        .then(() => {
          const roster = User.getRoster();

          roster.id.should.be.empty;
          roster.list.length.should.equal(ROSTER.list.length + 1);

          let aggregatePoint = CURVE_ED25519.point();
          let publicPoint = CURVE_ED25519.point();

          aggregatePoint.unmarshalBinary(ROSTER.aggregate);
          publicPoint.unmarshalBinary(CONODE_PUBLIC_KEY_BYTE_ARRAY);

          const aggregate = Crypto.aggregatePublicKeys([aggregatePoint, publicPoint]);
          roster.aggregate.should.deep.equal(aggregate);
        });
    });
  });

  describe("#substractRoster", function () {
    it("should throw an error when roster is not a roster", function () {
      expect(() => User.substractRoster("ROSTER")).to.throw();
    });

    it("should correctly remove when current roster is empty", function () {
      return User.substractRoster(ROSTER)
        .then(() => {
          const roster = User.getRoster();

          roster.id.should.be.empty;
          roster.list.should.be.empty;
          roster.aggregate.should.be.empty;
        });
    });

    it("should correctly remove the complete same roster", function () {
      return User.addRoster(ROSTER)
        .then(() => {
          return User.substractRoster(ROSTER);
        })
        .then(() => {
          const roster = User.getRoster();

          roster.id.should.be.empty;
          roster.list.should.be.empty;
          roster.aggregate.should.be.empty;
        });
    });

    it("should correctly remove when current roster is not empty", function () {
      return User.addRoster(ROSTER)
        .then(() => {
          return User.substractRoster(ROSTER_2);
        })
        .then(() => {
          const roster = User.getRoster();

          roster.id.should.be.empty;
          roster.list.length.should.equal(ROSTER.list.length - 1);

          let point1 = CURVE_ED25519.point();
          let point2 = CURVE_ED25519.point();

          point1.unmarshalBinary(Convert.base64ToByteArray("Fx6zzvJM6VzxfByLY2+uArGPtd2lHKPVmoXGMhdaFCA="));
          point2.unmarshalBinary(Convert.base64ToByteArray("j53MMKZNdtLlglcK9Ct1YYtkbbEOfq3R8ZoJOFIu6tE="));

          const aggregate = Crypto.aggregatePublicKeys([point1, point2]);
          roster.aggregate.should.deep.equal(aggregate);
        });
    });
  });

  describe("#substractServerByIndex", function () {
    it("should throw an error when index is not a number", function () {
      expect(() => User.substractServerByIndex("0")).to.throw();
    });

    it("should throw an error when index is negative", function () {
      expect(() => User.substractServerByIndex(-2)).to.throw();
    });

    it("should throw an error when index is too big", function () {
      return User.addRoster(ROSTER)
        .then(() => {
          return User.substractServerByIndex(ROSTER.list.length);
        }).should.be.rejected;
    });

    it("should correctly remove the server at the given index", function () {
      return User.addRoster(ROSTER)
        .then(() => {
          return User.substractServerByIndex(0);
        })
        .then(() => {
          return User.substractServerByIndex(0);
        })
        .then(() => {
          const roster = User.getRoster();

          roster.id.should.be.empty;
          roster.list.length.should.equal(1);
          roster.aggregate.should.deep.equal(Convert.base64ToByteArray("j53MMKZNdtLlglcK9Ct1YYtkbbEOfq3R8ZoJOFIu6tE="));
        });
    });
  });

  describe("#setRoster", function () {
    it("should throw an error when roster is not a roster", function () {
      expect(() => User.setRoster("ROSTER", true)).to.throw();
    });

    it("should throw an error when save is not a boolean", function () {
      expect(() => User.setRoster(ROSTER, "true")).to.throw();
    });

    it("should save if save is true", function () {
      return User.setRoster(ROSTER, true)
        .then(() => {
          return FileIO.getStringOf(FilesPath.ROSTER);
        })
        .then(rosterString => {
          const expectedRoster = Convert.objectToJson(ROSTER);

          rosterString.should.equal(expectedRoster);
        });
    });

    it("should not save if save is false", function () {
      return User.setRoster(ROSTER, false)
        .then(() => {
          return FileIO.getStringOf(FilesPath.ROSTER);
        })
        .then(rosterString => {
          rosterString.should.equal("");
        });
    });

    it("should correctly store the new roster in memory when save is false", function () {
      return User.setRoster(ROSTER, false)
        .then(() => {
          User._roster.id.should.deep.equal(ROSTER.id);
          User._roster.list.length.should.equal(ROSTER.list.length);
          for (let i = 0; i < ROSTER.list.length; ++i) {
            User._roster.list.getItem(i).public.should.deep.equal(ROSTER.list[i].public);
            User._roster.list.getItem(i).id.should.deep.equal(ROSTER.list[i].id);
            User._roster.list.getItem(i).address.should.equal(ROSTER.list[i].address);
            User._roster.list.getItem(i).description.should.equal(ROSTER.list[i].description);
          }
          User._roster.aggregate.should.deep.equal(ROSTER.aggregate);
        });
    });

    it("should correctly store the new roster in memory when save is true", function () {
      return User.setRoster(ROSTER, true)
        .then(() => {
          User._roster.id.should.deep.equal(ROSTER.id);
          User._roster.list.length.should.equal(ROSTER.list.length);
          for (let i = 0; i < ROSTER.list.length; ++i) {
            User._roster.list.getItem(i).public.should.deep.equal(ROSTER.list[i].public);
            User._roster.list.getItem(i).id.should.deep.equal(ROSTER.list[i].id);
            User._roster.list.getItem(i).address.should.equal(ROSTER.list[i].address);
            User._roster.list.getItem(i).description.should.equal(ROSTER.list[i].description);
          }
          User._roster.aggregate.should.deep.equal(ROSTER.aggregate);
        });
    });
  });

  describe("#getRoster", function () {
    it("should return a roster object", function () {
      const roster = User.getRoster();

      Helper.isOfType(roster, ObjectType.ROSTER).should.be.true;
    });

    it("should return the same roster that has just been set", function () {
      return User.setRoster(ROSTER, true)
        .then(() => {
          const roster = User.getRoster();

          roster.id.should.deep.equal(ROSTER_ID_BYTE_ARRAY);
          roster.list.length.should.equal(ROSTER_LIST.length);
          for (let i = 0; i < ROSTER_LIST.length; ++i) {
            roster.list[i].public.should.deep.equal(ROSTER_LIST_BYTE_ARRAY[i].public);
            roster.list[i].id.should.deep.equal(ROSTER_LIST_BYTE_ARRAY[i].id);
            roster.list[i].address.should.equal(ROSTER_LIST_BYTE_ARRAY[i].address);
            roster.list[i].description.should.equal(ROSTER_LIST_BYTE_ARRAY[i].description);
          }
          roster.aggregate.should.deep.equal(ROSTER_AGGREGATE_BYTE_ARRAY);
        });
    });
  });

  describe("#getRosterModule", function () {
    it("should return the reference to the observable module", function () {
      (User.getRosterModule() === User._roster).should.be.true;
    });
  });

  describe("#_setKeyPair", function () {
    it("should throw an error when keyPair is not a key pair", function () {
      expect(() => User._setKeyPair("KEY_PAIR", true)).to.throw();
    });

    it("should throw an error when save is not a boolean", function () {
      expect(() => User._setKeyPair(KEY_PAIR, "true")).to.throw();
    });

    it("should save if save is true", function () {
      return User._setKeyPair(KEY_PAIR, true)
        .then(() => {
          return FileIO.getStringOf(FileIO.join(FilesPath.USER_PATH, FilesPath.KEY_PAIR));
        })
        .then(keyPairString => {
          const expectedKeyPair = Convert.objectToJson(KEY_PAIR);

          keyPairString.should.equal(expectedKeyPair);
        });
    });

    it("should not save if save is false", function () {
      return User._setKeyPair(KEY_PAIR, false)
        .then(() => {
          return FileIO.getStringOf(FileIO.join(FilesPath.USER_PATH, FilesPath.KEY_PAIR));
        })
        .then(keyPairString => {
          keyPairString.should.equal("");
        });
    });

    it("should correctly store the new key pair in memory when save is false", function () {
      return User._setKeyPair(KEY_PAIR, false)
        .then(() => {
          const keyPair = User.getKeyPair();

          keyPair.public.should.deep.equal(PUBLIC_KEY_BYTE_ARRAY);
          keyPair.private.should.deep.equal(PRIVATE_KEY_BYTE_ARRAY);
          keyPair.publicComplete.should.deep.equal(PUBLIC_COMPLETE_KEY_BYTE_ARRAY);
        });
    });

    it("should correctly store the new key pair in memory when save is true", function () {
      return User._setKeyPair(KEY_PAIR, true)
        .then(() => {
          const keyPair = User.getKeyPair();

          keyPair.public.should.deep.equal(PUBLIC_KEY_BYTE_ARRAY);
          keyPair.private.should.deep.equal(PRIVATE_KEY_BYTE_ARRAY);
          keyPair.publicComplete.should.deep.equal(PUBLIC_COMPLETE_KEY_BYTE_ARRAY);
        });
    });
  });

  describe("#getKeyPair", function () {
    it("should return a key pair object", function () {
      const keyPair = User.getKeyPair();

      Helper.isOfType(keyPair, ObjectType.KEY_PAIR).should.be.true;
    });

    it("should return the same key pair that has just been set", function () {
      return User._setKeyPair(KEY_PAIR, true)
        .then(() => {
          const keyPair = User.getKeyPair();

          keyPair.public.should.deep.equal(PUBLIC_KEY_BYTE_ARRAY);
          keyPair.private.should.deep.equal(PRIVATE_KEY_BYTE_ARRAY);
          keyPair.publicComplete.should.deep.equal(PUBLIC_COMPLETE_KEY_BYTE_ARRAY);
        });
    });
  });

  describe("#isLoaded", function () {
    it("should return the reference to the boolean", function () {
      (User.isLoaded() === User._isLoaded).should.be.true;
    });
  });

  describe("#isKeyPairSet", function () {
    it("should return true if and only if public and private are not empty", function () {
      User.isKeyPairSet().should.be.false;

      User.getKeyPairModule().public = PUBLIC_KEY_BYTE_ARRAY;
      User.isKeyPairSet().should.be.false;

      User.getKeyPairModule().private = PRIVATE_KEY_BYTE_ARRAY;
      User.isKeyPairSet().should.be.true;
    });
  });
});
