const ObservableModule = require("data/observable");
const ObservableArray = require("data/observable-array").ObservableArray;
const StatusExtractor = require("../../../shared/lib/dedjs/extractor/StatusExtractor");
const Helper = require("../../../shared/lib/dedjs/Helper");

const viewModel = ObservableModule.fromObject({
  statsList: new ObservableArray()
});

function ConodeStatsViewModel() {
  setUpConodeStatsList();

  return viewModel;
}

/**
 * Sets up the list of stats with properties and functions needed.
 */
function setUpConodeStatsList() {
  const myStatsList = viewModel.statsList;

  /**
   * Loads the stats into the list.
   * @param conodeStatus - the conode to fetch stats from
   */
  myStatsList.load = function (conodeStatus) {
    let stat = {
      title: "",
      info: ""
    };

    stat.title = "Description";
    stat.info = StatusExtractor.getDescription(conodeStatus);
    pushStat(viewModel.statsList, Helper.deepCopy(stat));

    stat.title = "Address";
    stat.info = StatusExtractor.getAddress(conodeStatus);
    pushStat(viewModel.statsList, Helper.deepCopy(stat));

    stat.title = "ID (hex)";
    stat.info = StatusExtractor.getID(conodeStatus);
    pushStat(viewModel.statsList, Helper.deepCopy(stat));

    stat.title = "Public Key (hex)";
    stat.info = StatusExtractor.getPublicKey(conodeStatus);
    pushStat(viewModel.statsList, Helper.deepCopy(stat));

    stat.title = "Services";
    stat.info = StatusExtractor.getServices(conodeStatus);
    pushStat(viewModel.statsList, Helper.deepCopy(stat));

    stat.title = "System";
    stat.info = StatusExtractor.getSystem(conodeStatus);
    pushStat(viewModel.statsList, Helper.deepCopy(stat));

    stat.title = "Host";
    stat.info = StatusExtractor.getHost(conodeStatus);
    pushStat(viewModel.statsList, Helper.deepCopy(stat));

    stat.title = "Port";
    stat.info = StatusExtractor.getPort(conodeStatus);
    pushStat(viewModel.statsList, Helper.deepCopy(stat));

    stat.title = "ConnectionType";
    stat.info = StatusExtractor.getConnectionType(conodeStatus);
    pushStat(viewModel.statsList, Helper.deepCopy(stat));

    stat.title = "Version";
    stat.info = StatusExtractor.getVersion(conodeStatus);
    pushStat(viewModel.statsList, Helper.deepCopy(stat));

    stat.title = "TX Bytes";
    stat.info = StatusExtractor.getTXBytes(conodeStatus);
    pushStat(viewModel.statsList, Helper.deepCopy(stat));

    stat.title = "RX Bytes";
    stat.info = StatusExtractor.getRXBytes(conodeStatus);
    pushStat(viewModel.statsList, Helper.deepCopy(stat));

    stat.title = "Uptime";
    stat.info = StatusExtractor.getUptime(conodeStatus);
    pushStat(viewModel.statsList, Helper.deepCopy(stat));
  };

  /**
   * Empties the list of stats.
   */
  myStatsList.empty = function () {
    while (myStatsList.length) {
      myStatsList.pop();
    }
  };
}

/**
 * Pushes a new stat into the list of stats.
 * @param list - the list to add to
 * @param statToAdd - the stat to add
 */
function pushStat(list, statToAdd) {
  list.push({
    info: statToAdd
  });
}

module.exports = ConodeStatsViewModel;
