const ChaiAsPromised = require("chai-as-promised");
chai.use(ChaiAsPromised);
chai.should();

const FilesPath = require("../../../../../../shared/res/files/files-path");
const FileIO = require("../../../../../../shared/lib/file-io/file-io");
const Convert = require("../../../../../../shared/lib/dedjs/Convert");
const Helper = require("../../../../../../shared/lib/dedjs/Helper");
const ObjectType = require("../../../../../../shared/lib/dedjs/ObjectType");
const CothorityMessages = require("../../../../../../shared/lib/dedjs/network/cothority-messages");
const User = require("../../../../../../shared/lib/dedjs/object/user/User").get;
const PoP = require("../../../../../../shared/lib/dedjs/object/pop/PoP").get;

const OrgParty = require("../../../../../../shared/lib/dedjs/object/pop/org/OrgParty").Party;
const PARTY_FOLDER = "TEST_PARTY";
let Org = new OrgParty(PARTY_FOLDER);

const CONODE_ADDRESS = "tls://10.0.2.2:7002";
//const CONODE_ADDRESS = "tls://10.0.2.2:7004";
//const CONODE_ADDRESS = "tls://10.0.2.2:7006";
const CONODE_PUBLIC_KEY = "HkDzpR5Imd7WNx8kl2lJcIVRVn8gfDByJnmlfrYh/zU=";
//const CONODE_PUBLIC_KEY = "Fx6zzvJM6VzxfByLY2+uArGPtd2lHKPVmoXGMhdaFCA=";
//const CONODE_PUBLIC_KEY = "j53MMKZNdtLlglcK9Ct1YYtkbbEOfq3R8ZoJOFIu6tE=";
const CONODE_PUBLIC_KEY_BYTE_ARRAY = Convert.base64ToByteArray(CONODE_PUBLIC_KEY);
const CONODE_DESCRIPTION = "Conode_1";
//const CONODE_DESCRIPTION = "Conode_2";
//const CONODE_DESCRIPTION = "Conode_3";
const CONODE_ID_REAL = "z6kCTQ77Xna9yfgKka5lNQ==";
//const CONODE_ID_REAL = "Qd8XkrUlVEeClO9I95nklQ==";
//const CONODE_ID_REAL = "tUq+0651WRaAI4aTQC0d8w==";
const CONODE_ID_REAL_BYTE_ARRAY = Convert.base64ToByteArray(CONODE_ID_REAL);
const SERVER_IDENTITY = Convert.toServerIdentity(CONODE_ADDRESS, CONODE_PUBLIC_KEY_BYTE_ARRAY, CONODE_DESCRIPTION, CONODE_ID_REAL_BYTE_ARRAY);

const ROSTER_ID = "8yc0TaIweWRyMA==";
const ROSTER_ID_BYTE_ARRAY = Convert.base64ToByteArray(ROSTER_ID);
const ROSTER_LIST = [
  {
    "public": "HkDzpR5Imd7WNx8kl2lJcIVRVn8gfDByJnmlfrYh/zU=",
    "id": "z6kCTQ77Xna9yfgKka5lNQ==",
    "address": "tls://127.0.0.1:7002",
    "description": "Conode_1"
  },
  {
    "public": "Fx6zzvJM6VzxfByLY2+uArGPtd2lHKPVmoXGMhdaFCA=",
    "id": "Qd8XkrUlVEeClO9I95nklQ==",
    "address": "tls://127.0.0.1:7004",
    "description": "Conode_2"
  },
  {
    "public": "j53MMKZNdtLlglcK9Ct1YYtkbbEOfq3R8ZoJOFIu6tE=",
    "id": "tUq+0651WRaAI4aTQC0d8w==",
    "address": "tls://127.0.0.1:7006",
    "description": "Conode_3"
  }
];
const ROSTER_LIST_SERVER_IDENTITIES = ROSTER_LIST.map(conode => {
  conode.public = Convert.base64ToByteArray(conode.public);
  conode.id = Convert.base64ToByteArray(conode.id);

  return Convert.toServerIdentity(conode.address, conode.public, conode.description, conode.id);
});
const ROSTER_AGGREGATE = "q+G+7n6FXsY7hpxK3m119GuDHnchS6wqTE0sZE/fOKg=";
const ROSTER_AGGREGATE_BYTE_ARRAY = Convert.base64ToByteArray(ROSTER_AGGREGATE);

const POP_DESC_NAME = "Ced's Gang";
const POP_DESC_DATETIME = "Thu, 30 Nov 2017 11:12:00 GMT";
const POP_DESC_LOCATION = "INM, Lausanne";
const POP_DESC_ROSTER = CothorityMessages.createRoster(ROSTER_ID_BYTE_ARRAY, ROSTER_LIST_SERVER_IDENTITIES, ROSTER_AGGREGATE_BYTE_ARRAY);
const POP_DESC = CothorityMessages.createPopDesc(POP_DESC_NAME, POP_DESC_DATETIME, POP_DESC_LOCATION, POP_DESC_ROSTER);

let ATTENDEES = ["HkDzpR5Imd7WNx8kl2lJcIVRVn8gfDByJnmlfrYh/zU=", "Fx6zzvJM6VzxfByLY2+uArGPtd2lHKPVmoXGMhdaFCA=", "j53MMKZNdtLlglcK9Ct1YYtkbbEOfq3R8ZoJOFIu6tE="];
const REGISTERED_ATTS_JSON = Convert.objectToJson({
  array: Array.from(ATTENDEES)
});
ATTENDEES = ATTENDEES.map(base64Key => {
  return Convert.base64ToByteArray(base64Key);
});

const POP_DESC_HASH = "is4ISmQqzyEcbzTqDQEo6jP42SU4DTijtPYam5kwsoI=";
const POP_DESC_HASH_JSON = Convert.objectToJson({
  hash: POP_DESC_HASH
});
const POP_DESC_HASH_BYTE_ARRAY = Convert.base64ToByteArray(POP_DESC_HASH);

const PRIVATE_KEY = "AWKlOlcTuCHEV/fKX0X1IoAoBU0n1c5iKp/SWRLj3T4=";
//const PRIVATE_KEY = "Cce6tc8ZxYR1JlnFjHRgZvVCjfEpFf1pRNFPSGmOkr4=";
//const PRIVATE_KEY = "A+3lTDfz9oC/hCHPcggz6JwbId5cJ1PTjWhUArhCrfQ=";
const PRIVATE_KEY_BYTE_ARRAY = Convert.base64ToByteArray(PRIVATE_KEY);
const PUBLIC_KEY = "y4JMDWrle6RMV+0BKU92Xbu8+J8VkZ5kV3SvSr2ZxHw=";
//const PUBLIC_KEY = "6ggWOlIW50fgUWTRuHfKtI9OPdH1LCWPaV+USJS85Vk=";
//const PUBLIC_KEY = "roto8UHOJTWNHUSQGTptt1oAoNrkIirmPSteYCc5cDg=";
const PUBLIC_KEY_BYTE_ARRAY = Convert.base64ToByteArray(PUBLIC_KEY);
const PUBLIC_COMPLETE_KEY = "BBmiuL/uxUuItsuFVQJT4oUv4qZrb1fYQ+GL/ZTpZ43MfMSZvUqvdFdknpEVn/i8u112TykB7VdMpHvlag1Mgss=";
//const PUBLIC_COMPLETE_KEY = "BFSG/1tmjE+dTSgy5PIvGIRUmADtlHisVTtXdXdwwKfQWeW8lEiUX2mPJSz10T1Oj7TKd7jRZFHgR+cWUjoWCOo=";
//const PUBLIC_COMPLETE_KEY = "BCHV9x/kqfBnta5GTTzIaQvS1t+ZaxzO/+WE5BR8DnySOHA5J2BeKz3mKiLk2qAAWrdtOhmQRB2NNSXOQfFoi64=";
const PUBLIC_COMPLETE_KEY_BYTE_ARRAY = Convert.base64ToByteArray(PUBLIC_COMPLETE_KEY);
const JSON_KEY_PAIR = JSON.stringify({
  "private": PRIVATE_KEY,
  "public": PUBLIC_KEY,
  "publicComplete": PUBLIC_COMPLETE_KEY
});
const KEY_PAIR = Convert.parseJsonKeyPair(JSON_KEY_PAIR);

describe("Org", function () {

  function clean() {
    const promises = Object.getOwnPropertyNames(FilesPath).map(filePath => {
      return FileIO.writeStringTo(filePath, "");
    });

    promises.push(Org.remove());
    promises.push(User.reset());
    promises.push(PoP.reset());

    return Promise.all(promises)
      .then(() => {
        Org = new OrgParty(PARTY_FOLDER);
        return Promise.resolve();
      })
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

  it("should correctly load empty linked conode", function () {
    const linkedConode = Org.getLinkedConode();

    linkedConode.public.should.be.empty;
    linkedConode.id.should.be.empty;
    linkedConode.address.should.be.empty;
    linkedConode.description.should.be.empty;
  });

  it("should correctly load linked conode", function () {
    return FileIO.writeStringTo(FileIO.join(FilesPath.POP_ORG_PATH, PARTY_FOLDER, FilesPath.POP_ORG_CONODE), Convert.objectToJson(SERVER_IDENTITY))
      .then(() => {
        return Org.load();
      })
      .then(() => {
        const linkedConode = Org.getLinkedConode();

        linkedConode.public.should.deep.equal(CONODE_PUBLIC_KEY_BYTE_ARRAY);
        linkedConode.id.should.deep.equal(CONODE_ID_REAL_BYTE_ARRAY);
        linkedConode.address.should.equal(CONODE_ADDRESS);
        linkedConode.description.should.equal(CONODE_DESCRIPTION);
      });
  });

  it("should correctly load empty PopDesc", function () {
    const popDesc = Org.getPopDesc();

    popDesc.name.should.be.empty;
    popDesc.dateTime.should.be.empty;
    popDesc.location.should.be.empty;
    popDesc.roster.id.should.be.empty;
    popDesc.roster.list.should.be.empty;
    popDesc.roster.aggregate.should.be.empty;
  });

  it("should correctly load PopDesc", function () {
    return FileIO.writeStringTo(FileIO.join(FilesPath.POP_ORG_PATH, PARTY_FOLDER, FilesPath.POP_ORG_DESC), Convert.objectToJson(POP_DESC))
      .then(() => {
        return Org.load();
      })
      .then(() => {
        const popDesc = Org.getPopDesc();

        popDesc.name.should.equal(POP_DESC_NAME);
        popDesc.dateTime.should.equal(POP_DESC_DATETIME);
        popDesc.location.should.equal(POP_DESC_LOCATION);
        popDesc.roster.id.should.deep.equal(POP_DESC_ROSTER.id);

        popDesc.roster.list.length.should.equal(POP_DESC_ROSTER.list.length);
        for (let i = 0; i < POP_DESC_ROSTER.list.length; ++i) {
          popDesc.roster.list[i].public.should.deep.equal(POP_DESC_ROSTER.list[i].public);
          popDesc.roster.list[i].id.should.deep.equal(POP_DESC_ROSTER.list[i].id);
          popDesc.roster.list[i].address.should.equal(POP_DESC_ROSTER.list[i].address);
          popDesc.roster.list[i].description.should.equal(POP_DESC_ROSTER.list[i].description);
        }

        popDesc.roster.aggregate.should.deep.equal(POP_DESC_ROSTER.aggregate);
      });
  });

  it("should correctly load empty registered atts", function () {
    const registeredAtts = Org.getRegisteredAtts().slice();

    registeredAtts.should.be.empty;
  });

  it("should correctly load registered atts", function () {
    return FileIO.writeStringTo(FileIO.join(FilesPath.POP_ORG_PATH, PARTY_FOLDER, FilesPath.POP_ORG_ATTENDEES), REGISTERED_ATTS_JSON)
      .then(() => {
        return Org.load();
      })
      .then(() => {
        const registeredAtts = Org.getRegisteredAtts().slice();

        registeredAtts[0].should.deep.equal(ATTENDEES[0]);
        registeredAtts[1].should.deep.equal(ATTENDEES[1]);
        registeredAtts[2].should.deep.equal(ATTENDEES[2]);
      });
  });

  it("should correctly load empty PopDesc hash", function () {
    const popDescHash = Org.getPopDescHash();

    popDescHash.should.be.empty;
  });

  it("should correctly load PopDesc hash", function () {
    return FileIO.writeStringTo(FileIO.join(FilesPath.POP_ORG_PATH, PARTY_FOLDER, FilesPath.POP_ORG_DESC_HASH), POP_DESC_HASH_JSON)
      .then(() => {
        return Org.load();
      })
      .then(() => {
        const popDescHash = Org.getPopDescHash();

        popDescHash.should.deep.equal(POP_DESC_HASH_BYTE_ARRAY);
      });
  });

  it("should correctly reset", function () {
    const promises = [
      FileIO.writeStringTo(FileIO.join(FilesPath.POP_ORG_PATH, PARTY_FOLDER, FilesPath.POP_ORG_CONODE), Convert.objectToJson(SERVER_IDENTITY)),
      FileIO.writeStringTo(FileIO.join(FilesPath.POP_ORG_PATH, PARTY_FOLDER, FilesPath.POP_ORG_DESC), Convert.objectToJson(POP_DESC)),
      FileIO.writeStringTo(FileIO.join(FilesPath.POP_ORG_PATH, PARTY_FOLDER, FilesPath.POP_ORG_ATTENDEES), REGISTERED_ATTS_JSON),
      FileIO.writeStringTo(FileIO.join(FilesPath.POP_ORG_PATH, PARTY_FOLDER, FilesPath.POP_ORG_DESC_HASH), POP_DESC_HASH_JSON)
    ];

    return Promise.all(promises)
      .then(() => {
        return Org.load();
      })
      .then(() => {
        const otherPromises = [
          FileIO.getStringOf(FileIO.join(FilesPath.POP_ORG_PATH, PARTY_FOLDER, FilesPath.POP_ORG_CONODE)),
          FileIO.getStringOf(FileIO.join(FilesPath.POP_ORG_PATH, PARTY_FOLDER, FilesPath.POP_ORG_DESC)),
          FileIO.getStringOf(FileIO.join(FilesPath.POP_ORG_PATH, PARTY_FOLDER, FilesPath.POP_ORG_ATTENDEES)),
          FileIO.getStringOf(FileIO.join(FilesPath.POP_ORG_PATH, PARTY_FOLDER, FilesPath.POP_ORG_DESC_HASH))
        ];

        return Promise.all(otherPromises);
      })
      .then(strings => {
        const linkedConode = Org.getLinkedConode();
        linkedConode.public.should.not.be.empty;
        linkedConode.id.should.not.be.empty;
        linkedConode.address.should.not.be.empty;
        linkedConode.description.should.not.be.empty;

        const popDesc = Org.getPopDesc();
        popDesc.name.should.not.be.empty;
        popDesc.dateTime.should.not.be.empty;
        popDesc.location.should.not.be.empty;
        popDesc.roster.id.should.not.be.empty;
        popDesc.roster.list.should.not.be.empty;
        popDesc.roster.aggregate.should.not.be.empty;

        const registeredAtts = Org.getRegisteredAtts().slice();
        registeredAtts.should.not.be.empty;

        const popDescHash = Org.getPopDescHash();
        popDescHash.should.not.be.empty;

        strings.forEach(string => {
          string.should.not.be.empty;
        });

        return Org.reset();
      })
      .then(() => {
        const linkedConode = Org.getLinkedConode();
        linkedConode.public.should.be.empty;
        linkedConode.id.should.be.empty;
        linkedConode.address.should.be.empty;
        linkedConode.description.should.be.empty;

        const popDesc = Org.getPopDesc();
        popDesc.name.should.be.empty;
        popDesc.dateTime.should.be.empty;
        popDesc.location.should.be.empty;
        popDesc.roster.id.should.be.empty;
        popDesc.roster.list.should.be.empty;
        popDesc.roster.aggregate.should.be.empty;

        const registeredAtts = Org.getRegisteredAtts().slice();
        registeredAtts.should.be.empty;

        const popDescHash = Org.getPopDescHash();
        popDescHash.should.be.empty;

        const otherPromises = [
          FileIO.getStringOf(FileIO.join(FilesPath.POP_ORG_PATH, PARTY_FOLDER, FilesPath.POP_ORG_CONODE)),
          FileIO.getStringOf(FileIO.join(FilesPath.POP_ORG_PATH, PARTY_FOLDER, FilesPath.POP_ORG_DESC)),
          FileIO.getStringOf(FileIO.join(FilesPath.POP_ORG_PATH, PARTY_FOLDER, FilesPath.POP_ORG_ATTENDEES)),
          FileIO.getStringOf(FileIO.join(FilesPath.POP_ORG_PATH, PARTY_FOLDER, FilesPath.POP_ORG_DESC_HASH))
        ];

        return Promise.all(otherPromises);
      })
      .then(strings => {
        strings.forEach(string => {
          string.should.be.empty;
        });
      });
  });

  describe("#emptyPopDescRosterList", function () {
    it("should completely empty the roster list", function () {
      for (let i = 0; i < 100; ++i) {
        Org._popDesc.roster.list.push(i);
      }

      Org.emptyPopDescRosterList();

      Org._popDesc.roster.list.length.should.be.equal(0);
    });
  });

  describe("#emptyRegisteredAttsArray", function () {
    it("should completely empty the roster list", function () {
      for (let i = 0; i < 100; ++i) {
        Org._registeredAtts.array.push(i);
      }

      Org.emptyRegisteredAttsArray();

      Org._registeredAtts.array.length.should.be.equal(0);
    });
  });

  describe("#isLoaded", function () {
    it("should return reference to the variable", function () {
      (Org._isLoaded === Org.isLoaded()).should.be.true;
    });
  });

  describe("#getLinkedConodeModule", function () {
    it("should return reference to the variable", function () {
      (Org._linkedConode === Org.getLinkedConodeModule()).should.be.true;
    });
  });

  describe("#getLinkedConode", function () {
    it("should return a ServerIdentity object", function () {
      const linkedConode = Org.getLinkedConode();

      (Helper.isOfType(linkedConode, ObjectType.SERVER_IDENTITY)).should.be.true;
    });

    it("should correctly create the conode", function () {
      return Org.setLinkedConode(SERVER_IDENTITY, false)
        .then(() => {
          const linkedConode = Org.getLinkedConode();

          linkedConode.public.should.deep.equal(CONODE_PUBLIC_KEY_BYTE_ARRAY);
          linkedConode.id.should.deep.equal(CONODE_ID_REAL_BYTE_ARRAY);
          linkedConode.address.should.equal(CONODE_ADDRESS);
          linkedConode.description.should.equal(CONODE_DESCRIPTION);
        });
    });
  });

  describe("#setLinkedConode", function () {
    it("should throw an error when conode is not a ServerIdentity", function () {
      expect(() => Org.setLinkedConode("SERVER_IDENTITY", true)).to.throw();
    });

    it("should throw an error when save is not a boolean", function () {
      expect(() => Org.setLinkedConode(SERVER_IDENTITY, "true")).to.throw();
    });

    it("should save if save is true", function () {
      return Org.setLinkedConode(SERVER_IDENTITY, true)
        .then(() => {
          const linkedConode = Org.getLinkedConode();

          linkedConode.public.should.deep.equal(CONODE_PUBLIC_KEY_BYTE_ARRAY);
          linkedConode.id.should.deep.equal(CONODE_ID_REAL_BYTE_ARRAY);
          linkedConode.address.should.equal(CONODE_ADDRESS);
          linkedConode.description.should.equal(CONODE_DESCRIPTION);

          return FileIO.getStringOf(FileIO.join(FilesPath.POP_ORG_PATH, PARTY_FOLDER, FilesPath.POP_ORG_CONODE));
        })
        .then(linkedConodeString => {
          linkedConodeString.should.equal(Convert.objectToJson(SERVER_IDENTITY));
        });
    });

    it("should not save if save is false", function () {
      return Org.setLinkedConode(SERVER_IDENTITY, false)
        .then(() => {
          const linkedConode = Org.getLinkedConode();

          linkedConode.public.should.deep.equal(CONODE_PUBLIC_KEY_BYTE_ARRAY);
          linkedConode.id.should.deep.equal(CONODE_ID_REAL_BYTE_ARRAY);
          linkedConode.address.should.equal(CONODE_ADDRESS);
          linkedConode.description.should.equal(CONODE_DESCRIPTION);

          return FileIO.getStringOf(FileIO.join(FilesPath.POP_ORG_PATH, PARTY_FOLDER, FilesPath.POP_ORG_CONODE));
        })
        .then(linkedConodeString => {
          linkedConodeString.should.be.empty;
        });
    });
  });

  describe("#getPopDescModule", function () {
    it("should return reference to the variable", function () {
      (Org._popDesc === Org.getPopDescModule()).should.be.true;
    });
  });

  describe("#getPopDesc", function () {
    it("should return a PopDesc object", function () {
      const popDesc = Org.getPopDesc();

      (Helper.isOfType(popDesc, ObjectType.POP_DESC)).should.be.true;
    });

    it("should correctly create the PopDesc", function () {
      return Org.setPopDesc(POP_DESC, false)
        .then(() => {
          const popDesc = Org.getPopDesc();

          popDesc.name.should.equal(POP_DESC_NAME);
          popDesc.dateTime.should.equal(POP_DESC_DATETIME);
          popDesc.location.should.equal(POP_DESC_LOCATION);
          popDesc.roster.id.should.deep.equal(POP_DESC_ROSTER.id);

          popDesc.roster.list.length.should.equal(POP_DESC_ROSTER.list.length);
          for (let i = 0; i < POP_DESC_ROSTER.list.length; ++i) {
            popDesc.roster.list[i].public.should.deep.equal(POP_DESC_ROSTER.list[i].public);
            popDesc.roster.list[i].id.should.deep.equal(POP_DESC_ROSTER.list[i].id);
            popDesc.roster.list[i].address.should.equal(POP_DESC_ROSTER.list[i].address);
            popDesc.roster.list[i].description.should.equal(POP_DESC_ROSTER.list[i].description);
          }

          popDesc.roster.aggregate.should.deep.equal(POP_DESC_ROSTER.aggregate);
        });
    });
  });

  describe("#setPopDesc", function () {
    it("should throw an error when popDesc is not a PopDesc", function () {
      expect(() => Org.setPopDesc("POP_DESC", true)).to.throw();
    });

    it("should throw an error when save is not a boolean", function () {
      expect(() => Org.setPopDesc(POP_DESC, "true")).to.throw();
    });

    it("should save if save is true", function () {
      return Org.setPopDesc(POP_DESC, true)
        .then(() => {
          const popDesc = Org.getPopDesc();

          popDesc.name.should.equal(POP_DESC_NAME);
          popDesc.dateTime.should.equal(POP_DESC_DATETIME);
          popDesc.location.should.equal(POP_DESC_LOCATION);
          popDesc.roster.id.should.deep.equal(POP_DESC_ROSTER.id);

          popDesc.roster.list.length.should.equal(POP_DESC_ROSTER.list.length);
          for (let i = 0; i < POP_DESC_ROSTER.list.length; ++i) {
            popDesc.roster.list[i].public.should.deep.equal(POP_DESC_ROSTER.list[i].public);
            popDesc.roster.list[i].id.should.deep.equal(POP_DESC_ROSTER.list[i].id);
            popDesc.roster.list[i].address.should.equal(POP_DESC_ROSTER.list[i].address);
            popDesc.roster.list[i].description.should.equal(POP_DESC_ROSTER.list[i].description);
          }

          popDesc.roster.aggregate.should.deep.equal(POP_DESC_ROSTER.aggregate);

          return FileIO.getStringOf(FileIO.join(FilesPath.POP_ORG_PATH, PARTY_FOLDER, FilesPath.POP_ORG_DESC));
        })
        .then(popDescString => {
          popDescString.should.equal(Convert.objectToJson(POP_DESC));
        });
    });

    it("should not save if save is false", function () {
      return Org.setPopDesc(POP_DESC, false)
        .then(() => {
          const popDesc = Org.getPopDesc();

          popDesc.name.should.equal(POP_DESC_NAME);
          popDesc.dateTime.should.equal(POP_DESC_DATETIME);
          popDesc.location.should.equal(POP_DESC_LOCATION);
          popDesc.roster.id.should.deep.equal(POP_DESC_ROSTER.id);

          popDesc.roster.list.length.should.equal(POP_DESC_ROSTER.list.length);
          for (let i = 0; i < POP_DESC_ROSTER.list.length; ++i) {
            popDesc.roster.list[i].public.should.deep.equal(POP_DESC_ROSTER.list[i].public);
            popDesc.roster.list[i].id.should.deep.equal(POP_DESC_ROSTER.list[i].id);
            popDesc.roster.list[i].address.should.equal(POP_DESC_ROSTER.list[i].address);
            popDesc.roster.list[i].description.should.equal(POP_DESC_ROSTER.list[i].description);
          }

          popDesc.roster.aggregate.should.deep.equal(POP_DESC_ROSTER.aggregate);

          return FileIO.getStringOf(FileIO.join(FilesPath.POP_ORG_PATH, PARTY_FOLDER, FilesPath.POP_ORG_DESC));
        })
        .then(popDescString => {
          popDescString.should.be.empty;
        });
    });
  });

  describe("#getRegisteredAttsModule", function () {
    it("should return reference to the variable", function () {
      (Org._registeredAtts === Org.getRegisteredAttsModule()).should.be.true;
    });
  });

  describe("#getRegisteredAtts", function () {
    it("should return reference to the variable", function () {
      (Org._registeredAtts.array === Org.getRegisteredAtts()).should.be.true;
    });
  });

  describe("#setRegisteredAtts", function () {
    it("should throw an error when array is not an array", function () {
      expect(() => Org.setRegisteredAtts("ATTENDEES", true)).to.throw();
    });

    it("should throw an error when save is not a boolean", function () {
      expect(() => Org.setRegisteredAtts(ATTENDEES, "true")).to.throw();
    });

    it("should save if save is true", function () {
      return Org.setRegisteredAtts(ATTENDEES, true)
        .then(() => {
          const registeredAtts = Org.getRegisteredAtts();

          registeredAtts.getItem(0).should.deep.equal(ATTENDEES[0]);
          registeredAtts.getItem(1).should.deep.equal(ATTENDEES[1]);
          registeredAtts.getItem(2).should.deep.equal(ATTENDEES[2]);

          return FileIO.getStringOf(FileIO.join(FilesPath.POP_ORG_PATH, PARTY_FOLDER, FilesPath.POP_ORG_ATTENDEES));
        })
        .then(registeredAttsString => {
          registeredAttsString.should.equal(REGISTERED_ATTS_JSON);
        });
    });

    it("should not save if save is false", function () {
      return Org.setRegisteredAtts(ATTENDEES, false)
        .then(() => {
          const registeredAtts = Org.getRegisteredAtts();

          registeredAtts.getItem(0).should.deep.equal(ATTENDEES[0]);
          registeredAtts.getItem(1).should.deep.equal(ATTENDEES[1]);
          registeredAtts.getItem(2).should.deep.equal(ATTENDEES[2]);

          return FileIO.getStringOf(FileIO.join(FilesPath.POP_ORG_PATH, PARTY_FOLDER, FilesPath.POP_ORG_ATTENDEES));
        })
        .then(registeredAttsString => {
          registeredAttsString.should.be.empty;
        });
    });
  });

  describe("#getPopDescHashModule", function () {
    it("should return reference to the variable", function () {
      (Org._popDescHash === Org.getPopDescHashModule()).should.be.true;
    });
  });

  describe("#getPopDescHash", function () {
    it("should return reference to the variable", function () {
      (Org._popDescHash.hash === Org.getPopDescHash()).should.be.true;
    });
  });

  describe("#setPopDescHash", function () {
    it("should throw an error when array is not an array", function () {
      expect(() => Org.setPopDescHash("POP_DESC_HASH", true)).to.throw();
    });

    it("should throw an error when save is not boolean", function () {
      expect(() => Org.setPopDescHash(POP_DESC_HASH_BYTE_ARRAY, "true")).to.throw();
    });

    it("should save if save is true", function () {
      return Org.setPopDescHash(POP_DESC_HASH_BYTE_ARRAY, true)
        .then(() => {
          const popDescHash = Org.getPopDescHash();

          popDescHash.should.deep.equal(POP_DESC_HASH_BYTE_ARRAY);

          return FileIO.getStringOf(FileIO.join(FilesPath.POP_ORG_PATH, PARTY_FOLDER, FilesPath.POP_ORG_DESC_HASH));
        })
        .then(popDescHashString => {
          popDescHashString.should.equal(POP_DESC_HASH_JSON);
        });
    });

    it("should not save if save is false", function () {
      return Org.setPopDescHash(POP_DESC_HASH_BYTE_ARRAY, false)
        .then(() => {
          const popDescHash = Org.getPopDescHash();

          popDescHash.should.deep.equal(POP_DESC_HASH_BYTE_ARRAY);

          return FileIO.getStringOf(FileIO.join(FilesPath.POP_ORG_PATH, PARTY_FOLDER, FilesPath.POP_ORG_DESC_HASH));
        })
        .then(popDescHashString => {
          popDescHashString.should.be.empty;
        });
    });
  });

  describe("#setPopDescName", function () {
    it("should throw an error when name is not a string", function () {
      expect(() => Org.setPopDescName(42)).to.throw();
    });

    it("should correctly set and save the new name", function () {
      return Org.setPopDesc(POP_DESC, true)
        .then(() => {
          Org.setPopDescName("NEW_NAME");
        })
        .then(() => {
          const popDesc = Org.getPopDesc();

          popDesc.name.should.equal("NEW_NAME");

          return FileIO.getStringOf(FileIO.join(FilesPath.POP_ORG_PATH, PARTY_FOLDER, FilesPath.POP_ORG_DESC));
        })
        .then(popDescString => {
          const popDescObject = Convert.jsonToObject(popDescString);

          popDescObject.name.should.equal("NEW_NAME");
        });
    });
  });

  describe("#setPopDescDateTime", function () {
    it("should throw an error when dateTime is not a string", function () {
      expect(() => Org.setPopDescDateTime(42)).to.throw();
    });

    it("should correctly set and save the new dateTime", function () {
      return Org.setPopDesc(POP_DESC, true)
        .then(() => {
          Org.setPopDescDateTime("NEW_DATETIME");
        })
        .then(() => {
          const popDesc = Org.getPopDesc();

          popDesc.dateTime.should.equal("NEW_DATETIME");

          return FileIO.getStringOf(FileIO.join(FilesPath.POP_ORG_PATH, PARTY_FOLDER, FilesPath.POP_ORG_DESC));
        })
        .then(popDescString => {
          const popDescObject = Convert.jsonToObject(popDescString);

          popDescObject.dateTime.should.equal("NEW_DATETIME");
        });
    });
  });

  describe("#setPopDescLocation", function () {
    it("should throw an error when location is not a string", function () {
      expect(() => Org.setPopDescLocation(42)).to.throw();
    });

    it("should correctly set and save the new location", function () {
      return Org.setPopDesc(POP_DESC, true)
        .then(() => {
          Org.setPopDescLocation("NEW_LOCATION");
        })
        .then(() => {
          const popDesc = Org.getPopDesc();

          popDesc.location.should.equal("NEW_LOCATION");

          return FileIO.getStringOf(FileIO.join(FilesPath.POP_ORG_PATH, PARTY_FOLDER, FilesPath.POP_ORG_DESC));
        })
        .then(popDescString => {
          const popDescObject = Convert.jsonToObject(popDescString);

          popDescObject.location.should.equal("NEW_LOCATION");
        });
    });
  });

  describe("#addPopDescConode", function () {
    it("should throw an error when conode is not a ServerIdentity", function () {
      expect(() => Org.addPopDescConode("SERVER_IDENTITY")).to.throw();
    });

    it("should correctly add and save the new conode", function () {
      return Org.setPopDesc(POP_DESC, true)
        .then(() => {
          Org.addPopDescConode(SERVER_IDENTITY);
        })
        .then(() => {
          const popDesc = Org.getPopDesc();

          popDesc.roster.list.length.should.equal(POP_DESC_ROSTER.list.length + 1);

          return FileIO.getStringOf(FileIO.join(FilesPath.POP_ORG_PATH, PARTY_FOLDER, FilesPath.POP_ORG_DESC));
        })
        .then(popDescString => {
          const popDescObject = Convert.jsonToObject(popDescString);

          popDescObject.roster.list.length.should.equal(POP_DESC_ROSTER.list.length + 1);
        });
    });
  });

  describe("#removePopDescConodeByIndex", function () {
    it("should throw an error when index is not a number", function () {
      expect(() => Org.removePopDescConodeByIndex("1")).to.throw();
    });

    it("should correctly add and save the new conode", function () {
      console.log("SKDEBUG before : " + POP_DESC);
      return Org.setPopDesc(POP_DESC, true)
        .then(() => {
          Org.removePopDescConodeByIndex(1);
        })
        .then(() => {
          const popDesc = Org.getPopDesc();

          popDesc.roster.list.length.should.equal(POP_DESC_ROSTER.list.length - 1);

          return FileIO.getStringOf(FileIO.join(FilesPath.POP_ORG_PATH, PARTY_FOLDER, FilesPath.POP_ORG_DESC));
        })
        .then(popDescString => {
          const popDescObject = Convert.jsonToObject(popDescString);
          console.log("SKDEBUG after : " + popDescString);

          popDescObject.roster.list.length.should.equal(POP_DESC_ROSTER.list.length - 1);
        });
    });
  });

  describe("#registerAttendee", function () {
    it("should throw an error when publicKey is not a byte array", function () {
      expect(() => Org.registerAttendee("CONODE_PUBLIC_KEY_BYTE_ARRAY")).to.throw();
    });

    it("should correctly add and save the new attendee", function () {
      return Org.setRegisteredAtts(ATTENDEES, true)
        .then(() => {
          Org.registerAttendee(CONODE_PUBLIC_KEY_BYTE_ARRAY);
        })
        .then(() => {
          const registeredAttendees = Org.getRegisteredAtts().slice();

          registeredAttendees.length.should.equal(ATTENDEES.length + 1);

          return FileIO.getStringOf(FileIO.join(FilesPath.POP_ORG_PATH, PARTY_FOLDER, FilesPath.POP_ORG_ATTENDEES));
        })
        .then(registeredAttendeesString => {
          const registeredAttendeesObject = Convert.jsonToObject(registeredAttendeesString);

          registeredAttendeesObject.array.length.should.equal(ATTENDEES.length + 1);
        });
    });
  });

  describe("#unregisterAttendeeByIndex", function () {
    it("should throw an error when index is not a number", function () {
      expect(() => Org.unregisterAttendeeByIndex("1")).to.throw();
    });

    it("should correctly add and save the new attendee", function () {
      return Org.setRegisteredAtts(ATTENDEES, true)
        .then(() => {
          Org.unregisterAttendeeByIndex(1);
        })
        .then(() => {
          const registeredAttendees = Org.getRegisteredAtts().slice();

          registeredAttendees.length.should.equal(ATTENDEES.length - 1);

          return FileIO.getStringOf(FileIO.join(FilesPath.POP_ORG_PATH, PARTY_FOLDER, FilesPath.POP_ORG_ATTENDEES));
        })
        .then(registeredAttendeesString => {
          const registeredAttendeesObject = Convert.jsonToObject(registeredAttendeesString);

          registeredAttendeesObject.array.length.should.equal(ATTENDEES.length - 1);
        });
    });
  });

  describe("#isLinkedConodeSet", function () {
    it("should return true if and only if all field of the conodes are non empty", function () {
      Org.isLinkedConodeSet().should.be.false;

      Org._linkedConode.public = CONODE_PUBLIC_KEY_BYTE_ARRAY;
      Org.isLinkedConodeSet().should.be.false;

      Org._linkedConode.id = CONODE_ID_REAL_BYTE_ARRAY;
      Org.isLinkedConodeSet().should.be.false;

      Org._linkedConode.address = CONODE_ADDRESS;
      Org.isLinkedConodeSet().should.be.false;

      Org._linkedConode.description = CONODE_DESCRIPTION;
      Org.isLinkedConodeSet().should.be.true;
    });
  });

  describe("#isPopDescBeingSet", function () {
    it("should return true if and only if at least one field of the PopDesc is non empty", function () {
      Org.isPopDescBeingSet().should.be.false;

      Org._popDesc.name = POP_DESC_NAME;
      Org.isPopDescBeingSet().should.be.true;

      Org._popDesc.dateTime = POP_DESC_DATETIME;
      Org.isPopDescBeingSet().should.be.true;

      Org._popDesc.location = POP_DESC_LOCATION;
      Org.isPopDescBeingSet().should.be.true;

      Org._popDesc.roster.list = POP_DESC_ROSTER.list;
      Org.isPopDescBeingSet().should.be.true;
    });
  });

  describe("#isPopDescComplete", function () {
    it("should return true if and only if all field of the PopDesc are non empty and contains at least 3 conodes", function () {
      Org.isPopDescComplete().should.be.false;

      Org._popDesc.name = POP_DESC_NAME;
      Org.isPopDescComplete().should.be.false;

      Org._popDesc.dateTime = POP_DESC_DATETIME;
      Org.isPopDescComplete().should.be.false;

      Org._popDesc.location = POP_DESC_LOCATION;
      Org.isPopDescComplete().should.be.false;

      Org._popDesc.roster.list = [SERVER_IDENTITY, SERVER_IDENTITY];
      Org.isPopDescComplete().should.be.false;

      Org._popDesc.roster.list = [SERVER_IDENTITY, SERVER_IDENTITY, SERVER_IDENTITY];
      Org.isPopDescComplete().should.be.true;
    });
  });

  describe("#linkToConode", function () {
    it("should throw an error when conode is not a ServerIdentity", function () {
      expect(() => {
        User._keyPair.public = PUBLIC_KEY_BYTE_ARRAY;
        User._keyPair.private = PRIVATE_KEY_BYTE_ARRAY;

        Org.linkToConode("SERVER_IDENTITY", "123456");
      }).to.throw();
    });

    it("should throw an error when pin is not a string", function () {
      expect(() => {
        User._keyPair.public = PUBLIC_KEY_BYTE_ARRAY;
        User._keyPair.private = PRIVATE_KEY_BYTE_ARRAY;

        Org.linkToConode(SERVER_IDENTITY, 123456);
      }).to.throw();
    });

    it("should throw an error when the user's key pair is not a set", function () {
      expect(() => Org.linkToConode(SERVER_IDENTITY, "123456")).to.throw();
    });

    /*
    it.only("should link and set the linked conode", function () {
      return User.setKeyPair(KEY_PAIR, false)
        .then(() => {
          return Org.linkToConode(SERVER_IDENTITY, "");
        })
        .then(response => {
          console.log(response);
          console.dir(response);

          const linkedConode = Org.getLinkedConode();

          linkedConode.public.should.deep.equal(CONODE_PUBLIC_KEY_BYTE_ARRAY);
          linkedConode.id.should.deep.equal(CONODE_ID_REAL_BYTE_ARRAY);
          linkedConode.address.should.equal(CONODE_ADDRESS);
          linkedConode.description.should.equal(CONODE_DESCRIPTION);
        });
    });
    */
  });

  describe("#registerPopDesc", function () {
    it("should throw an error when the user's key pair is not set", function () {
      expect(() => {
        Org._popDesc.name = POP_DESC_NAME;
        Org._popDesc.dateTime = POP_DESC_DATETIME;
        Org._popDesc.location = POP_DESC_LOCATION;
        Org._popDesc.roster = POP_DESC_ROSTER;

        Org._linkedConode.public = CONODE_PUBLIC_KEY_BYTE_ARRAY;
        Org._linkedConode.id = CONODE_ID_REAL_BYTE_ARRAY;
        Org._linkedConode.address = CONODE_ADDRESS;
        Org._linkedConode.description = CONODE_DESCRIPTION;

        Org.registerPopDesc();
      }).to.throw();
    });

    it("should throw an error when PopDesc is not complete", function () {
      expect(() => {
        User._keyPair.public = PUBLIC_KEY_BYTE_ARRAY;
        User._keyPair.private = PRIVATE_KEY_BYTE_ARRAY;

        Org._linkedConode.public = CONODE_PUBLIC_KEY_BYTE_ARRAY;
        Org._linkedConode.id = CONODE_ID_REAL_BYTE_ARRAY;
        Org._linkedConode.address = CONODE_ADDRESS;
        Org._linkedConode.description = CONODE_DESCRIPTION;

        Org.registerPopDesc();
      }).to.throw();
    });

    it("should throw an error when not linked to conode", function () {
      expect(() => {
        User._keyPair.public = PUBLIC_KEY_BYTE_ARRAY;
        User._keyPair.private = PRIVATE_KEY_BYTE_ARRAY;

        Org._popDesc.name = POP_DESC_NAME;
        Org._popDesc.dateTime = POP_DESC_DATETIME;
        Org._popDesc.location = POP_DESC_LOCATION;
        Org._popDesc.roster = POP_DESC_ROSTER;

        Org.registerPopDesc();
      }).to.throw();
    });

    /*
    it.only("should register PopDesc and set the PopDesc's hash", function () {
      return User.setKeyPair(KEY_PAIR, false)
        .then(() => {
          return Org.setPopDesc(POP_DESC, false);
        })
        .then(() => {
          return Org.setLinkedConode(SERVER_IDENTITY, false);
        })
        .then(() => {
          return Org.registerPopDesc();
        })
        .then(response => {
          if (typeof response == "string") {
            console.log(response);
          } else {
            console.log(Convert.byteArrayToBase64(response));
            console.log(Convert.byteArrayToHex(response));
          }

          const linkedConode = Org.getLinkedConode();

          linkedConode.public.should.deep.equal(CONODE_PUBLIC_KEY_BYTE_ARRAY);
          linkedConode.id.should.deep.equal(CONODE_ID_REAL_BYTE_ARRAY);
          linkedConode.address.should.equal(CONODE_ADDRESS);
          linkedConode.description.should.equal(CONODE_DESCRIPTION);
        });
    });
    */
  });

  describe("#registerAttsAndFinalizeParty", function () {
    it("should throw an error when the user's key pair is not set", function () {
      expect(() => {
        Org._popDesc.name = POP_DESC_NAME;
        Org._popDesc.dateTime = POP_DESC_DATETIME;
        Org._popDesc.location = POP_DESC_LOCATION;
        Org._popDesc.roster = POP_DESC_ROSTER;

        Org._linkedConode.public = CONODE_PUBLIC_KEY_BYTE_ARRAY;
        Org._linkedConode.id = CONODE_ID_REAL_BYTE_ARRAY;
        Org._linkedConode.address = CONODE_ADDRESS;
        Org._linkedConode.description = CONODE_DESCRIPTION;

        Org._popDescHash.hash = POP_DESC_HASH_BYTE_ARRAY;

        Org._registeredAtts.array = ATTENDEES;

        Org.registerAttsAndFinalizeParty();
      }).to.throw();
    });

    it("should throw an error when the PopDesc is not complete", function () {
      expect(() => {
        User._keyPair.public = PUBLIC_KEY_BYTE_ARRAY;
        User._keyPair.private = PRIVATE_KEY_BYTE_ARRAY;

        Org._linkedConode.public = CONODE_PUBLIC_KEY_BYTE_ARRAY;
        Org._linkedConode.id = CONODE_ID_REAL_BYTE_ARRAY;
        Org._linkedConode.address = CONODE_ADDRESS;
        Org._linkedConode.description = CONODE_DESCRIPTION;

        Org._popDescHash.hash = POP_DESC_HASH_BYTE_ARRAY;

        Org._registeredAtts.array = ATTENDEES;

        Org.registerAttsAndFinalizeParty();
      }).to.throw();
    });

    it("should throw an error when not linked to a conode", function () {
      expect(() => {
        User._keyPair.public = PUBLIC_KEY_BYTE_ARRAY;
        User._keyPair.private = PRIVATE_KEY_BYTE_ARRAY;

        Org._popDesc.name = POP_DESC_NAME;
        Org._popDesc.dateTime = POP_DESC_DATETIME;
        Org._popDesc.location = POP_DESC_LOCATION;
        Org._popDesc.roster = POP_DESC_ROSTER;

        Org._popDescHash.hash = POP_DESC_HASH_BYTE_ARRAY;

        Org._registeredAtts.array = ATTENDEES;

        Org.registerAttsAndFinalizeParty();
      }).to.throw();
    });

    it("should throw an error when the PopDesc has not been registered on the conode", function () {
      expect(() => {
        User._keyPair.public = PUBLIC_KEY_BYTE_ARRAY;
        User._keyPair.private = PRIVATE_KEY_BYTE_ARRAY;

        Org._popDesc.name = POP_DESC_NAME;
        Org._popDesc.dateTime = POP_DESC_DATETIME;
        Org._popDesc.location = POP_DESC_LOCATION;
        Org._popDesc.roster = POP_DESC_ROSTER;

        Org._linkedConode.public = CONODE_PUBLIC_KEY_BYTE_ARRAY;
        Org._linkedConode.id = CONODE_ID_REAL_BYTE_ARRAY;
        Org._linkedConode.address = CONODE_ADDRESS;
        Org._linkedConode.description = CONODE_DESCRIPTION;

        Org._registeredAtts.array = ATTENDEES;

        Org.registerAttsAndFinalizeParty();
      }).to.throw();
    });

    it("should throw an error when there are no attendees to register", function () {
      expect(() => {
        User._keyPair.public = PUBLIC_KEY_BYTE_ARRAY;
        User._keyPair.private = PRIVATE_KEY_BYTE_ARRAY;

        Org._popDesc.name = POP_DESC_NAME;
        Org._popDesc.dateTime = POP_DESC_DATETIME;
        Org._popDesc.location = POP_DESC_LOCATION;
        Org._popDesc.roster = POP_DESC_ROSTER;

        Org._linkedConode.public = CONODE_PUBLIC_KEY_BYTE_ARRAY;
        Org._linkedConode.id = CONODE_ID_REAL_BYTE_ARRAY;
        Org._linkedConode.address = CONODE_ADDRESS;
        Org._linkedConode.description = CONODE_DESCRIPTION;

        Org._popDescHash.hash = POP_DESC_HASH_BYTE_ARRAY;

        Org.registerAttsAndFinalizeParty();
      }).to.throw();
    });

    /*
    it.only("should register attendees and save final statement if it is the last registration", function () {
      return User.setKeyPair(KEY_PAIR, false)
        .then(() => {
          return Org.setPopDesc(POP_DESC, false);
        })
        .then(() => {
          return Org.setLinkedConode(SERVER_IDENTITY, false);
        })
        .then(() => {
          return Org.registerPopDesc();
        })
        .then(descId => {
          return Org.setPopDescHash(descId, false);
        })
        .then(() => {
          return Org.setRegisteredAtts(ATTENDEES, false);
        })
        .then(() => {
          return Org.registerAttsAndFinalizeParty();
        })
        .then(() => {
          const finalStatements = PoP.getFinalStatements().slice();

          finalStatements.length.should.equal(1);
          console.log(finalStatements[0]);
          console.dir(finalStatements[0]);
        });
    });
    */
  });
});
