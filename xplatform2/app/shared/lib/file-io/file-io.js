/**
 * @file Library to ease file I/O using promises.
 */

const FileSystem = require("tns-core-modules/file-system");
const Documents = FileSystem.knownFolders.documents();

/**
 * Gets the string of the file at filePath and returns a promise with the content.
 * @param {string} filePath - the path to the file
 * @returns {Promise} - a promise that gets resolved once the content of the file has been read
 */
function getStringOf(filePath) {
  if (typeof filePath !== "string") {
    throw new Error("filePath must be of type string");
  }

  return Documents.getFile(filePath)
    .readText()
    .catch((error) => {
      console.log("READING ERROR:");
      console.log(error);
      console.dir(error);
      console.trace();
    });
}

/**
 * Writes the parameter string to the file at filePath. This method overwrites the file completely.
 * @param {string} filePath - the path to the file
 * @param {string} string - the string to write
 * @returns {Promise} - a promise that gets resolved once the content has been written to the file
 */
function writeStringTo(filePath, string) {
  if (typeof filePath !== "string") {
    throw new Error("filePath must be of type string");
  }
  if (typeof string !== "string") {
    throw new Error("string must be of type string");
  }

  return Documents.getFile(filePath)
    .writeText(string)
    .catch((error) => {
      console.log("WRITING ERROR:");
      console.log(error);
      console.dir(error);
      console.trace();
    });
}

/**
 * Execute a given function on each element of a folder.
 * @param {string} folder - the path to the folder
 * @param {function} closure - the function that will be exeuted on each element. It has to be of type
 * function (elementName: string)
 */
function forEachFolderElement(folder, closure) {
  if (typeof folder !== "string") {
    throw new Error("folder must be of type string");
  }

  if (typeof closure !== "function") {
    throw new Error("closure must be of type function");
  }

  Documents.getFolder(folder).eachEntity(function (entity) {
    closure(entity);

    // continue until the last file
    return true;
  })
}

/**
 * Remove the specified fodler
 * @param {string} folder
 * @retuns {Promise} - a promise that gets resolved once the folder has been deleted
 */
function removeFolder(folder) {
  if (typeof folder !== "string") {
    throw new Error("folder must be of type string");
  }

  return Documents.getFolder(folder).remove().catch((error) => {
    console.log("REMOVING ERROR :");
    console.log(error);
    console.dir(error);
    console.trace();
  });
}

function folderExists(path) {
    return FileSystem.Folder.exists(this.join(Documents.path, path));
}

function fileExists(path) {
    return FileSystem.Folder.exists(this.join(Documents.path, path));
}

module.exports.getStringOf = getStringOf;
module.exports.writeStringTo = writeStringTo;
module.exports.forEachFolderElement = forEachFolderElement;
module.exports.removeFolder = removeFolder;
module.exports.join = FileSystem.path.join;
module.exports.fileExists = fileExists;
module.exports.folderExists = folderExists;

