const ChaiAsPromised = require("chai-as-promised");
chai.use(ChaiAsPromised);
chai.should();

const CothorityMessages = require("../../../../shared/lib/dedjs/network/cothority-messages");
const ObjectType = require("../../../../shared/lib/dedjs/ObjectType");
const Convert = require("../../../../shared/lib/dedjs/Convert");

const StatusExtractor = require("../../../../shared/lib/dedjs/extractor/StatusExtractor");

const fields = {
  "system": {
    "Generic": {
      "field": {
        "Available_Services": "CoSi,Identity,PoPServer,Skipchain,Status",
        "Host": "127.0.0.1",
        "Port": "7002",
        "Description": "Conode_1",
        "ConnType": "tls",
        "Version": "1.2",
        "TX_bytes": "0",
        "RX_bytes": "0",
        "Uptime": "49.38793933s",
        "System": "linux/amd64/go1.9.2"
      }
    }
  },
  "server": {
    "public": "HkDzpR5Imd7WNx8kl2lJcIVRVn8gfDByJnmlfrYh/zU=",
    "id": "z6kCTQ77Xna9yfgKka5lNQ==",
    "address": "tls://127.0.0.1:7002",
    "description": "Conode_1"
  }
};
fields.server.public = Convert.base64ToByteArray(fields.server.public);
fields.server.id = Convert.base64ToByteArray(fields.server.id);

const statusResponse = CothorityMessages.getModel(ObjectType.STATUS_RESPONSE).create(fields);

describe("StatusExtractor", function () {
  describe("#getDescription", function () {
    it("should throw an error when statusResponse is not a status response", function () {
      expect(() => StatusExtractor.getDescription("statusResponse")).to.throw();
    });

    it("should correctly get back the description", function () {
      const description = StatusExtractor.getDescription(statusResponse);

      description.should.equal(fields.server.description);
    });
  });

  describe("#getAddress", function () {
    it("should throw an error when statusResponse is not a status response", function () {
      expect(() => StatusExtractor.getAddress("statusResponse")).to.throw();
    });

    it("should correctly get back the address", function () {
      const address = StatusExtractor.getAddress(statusResponse);

      address.should.equal(fields.server.address);
    });
  });

  describe("#getID", function () {
    it("should throw an error when statusResponse is not a status response", function () {
      expect(() => StatusExtractor.getID("statusResponse")).to.throw();
    });

    it("should correctly get back the id", function () {
      const id = StatusExtractor.getID(statusResponse);

      id.should.equal(Convert.byteArrayToHex(fields.server.id));
    });
  });

  describe("#getPublicKey", function () {
    it("should throw an error when statusResponse is not a status response", function () {
      expect(() => StatusExtractor.getPublicKey("statusResponse")).to.throw();
    });

    it("should correctly get back the public key", function () {
      const publicKey = StatusExtractor.getPublicKey(statusResponse);

      publicKey.should.equal(Convert.byteArrayToHex(fields.server.public));
    });
  });

  describe("#getServices", function () {
    it("should throw an error when statusResponse is not a status response", function () {
      expect(() => StatusExtractor.getServices("statusResponse")).to.throw();
    });

    it("should correctly get back the services", function () {
      const services = StatusExtractor.getServices(statusResponse);

      services.should.equal(fields.system.Generic.field.Available_Services);
    });
  });

  describe("#getSystem", function () {
    it("should throw an error when statusResponse is not a status response", function () {
      expect(() => StatusExtractor.getSystem("statusResponse")).to.throw();
    });

    it("should correctly get back the system", function () {
      const system = StatusExtractor.getSystem(statusResponse);

      system.should.equal(fields.system.Generic.field.System);
    });
  });

  describe("#getHost", function () {
    it("should throw an error when statusResponse is not a status response", function () {
      expect(() => StatusExtractor.getHost("statusResponse")).to.throw();
    });

    it("should correctly get back the host", function () {
      const host = StatusExtractor.getHost(statusResponse);

      host.should.equal(fields.system.Generic.field.Host);
    });
  });

  describe("#getPort", function () {
    it("should throw an error when statusResponse is not a status response", function () {
      expect(() => StatusExtractor.getPort("statusResponse")).to.throw();
    });

    it("should correctly get back the port", function () {
      const port = StatusExtractor.getPort(statusResponse);

      port.should.equal(fields.system.Generic.field.Port);
    });
  });

  describe("#getConnectionType", function () {
    it("should throw an error when statusResponse is not a status response", function () {
      expect(() => StatusExtractor.getConnectionType("statusResponse")).to.throw();
    });

    it("should correctly get back the connection type", function () {
      const connectionType = StatusExtractor.getConnectionType(statusResponse);

      connectionType.should.equal(fields.system.Generic.field.ConnType);
    });
  });

  describe("#getVersion", function () {
    it("should throw an error when statusResponse is not a status response", function () {
      expect(() => StatusExtractor.getVersion("statusResponse")).to.throw();
    });

    it("should correctly get back the version", function () {
      const version = StatusExtractor.getVersion(statusResponse);

      version.should.equal(fields.system.Generic.field.Version);
    });
  });

  describe("#getTXBytes", function () {
    it("should throw an error when statusResponse is not a status response", function () {
      expect(() => StatusExtractor.getTXBytes("statusResponse")).to.throw();
    });

    it("should correctly get back the TX bytes", function () {
      const txBytes = StatusExtractor.getTXBytes(statusResponse);

      txBytes.should.equal(fields.system.Generic.field.TX_bytes);
    });
  });

  describe("#getRXBytes", function () {
    it("should throw an error when statusResponse is not a status response", function () {
      expect(() => StatusExtractor.getRXBytes("statusResponse")).to.throw();
    });

    it("should correctly get back the RX bytes", function () {
      const rxBytes = StatusExtractor.getRXBytes(statusResponse);

      rxBytes.should.equal(fields.system.Generic.field.RX_bytes);
    });
  });

  describe("#getUptime", function () {
    it("should throw an error when statusResponse is not a status response", function () {
      expect(() => StatusExtractor.getUptime("statusResponse")).to.throw();
    });

    it("should correctly get back the uptime", function () {
      const upTime = StatusExtractor.getUptime(statusResponse);

      upTime.should.equal(fields.system.Generic.field.Uptime);
    });
  });
});
