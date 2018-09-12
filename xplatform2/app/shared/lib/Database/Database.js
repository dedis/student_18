var couchbaseModule = require("nativescript-couchbase");
var observableArrayModule = require("data/observable-array");
var frameModule = require("ui/frame");

class Database{


  constructor(databaseName, viewName){
      this.personList = new observableArrayModule.ObservableArray([]);
      this.database = new couchbaseModule.Couchbase(databaseName);
      this.docs= [] ;
      this.viewName= viewName;
      this.database.createView(viewName, "1", function(document, emitter) {
          emitter.emit(document._id, document);
      });


  }


clear(){
    this.personList.splice(0);

    var rows = this.database.executeQuery(this.viewName);
    for(var i in rows) {
        if(rows.hasOwnProperty(i)) {
            this.personList.push(rows[i]);
        }
    }
    for ( var s =0; s< this.personList.length; s++){
            this.database.deleteDocument(this.personList.getItem(s)._id);
        }


}
  getValue(id){
      this.personList.splice(0);

      var rows = this.database.executeQuery(this.viewName);
      for(var i in rows) {
          if(rows.hasOwnProperty(i)) {
              this.personList.push(rows[i]);
          }
      }
      for ( var s =0; s< this.personList.length; s++){

          if(this.personList.getItem(s).id===id){
              return Promise.resolve(this.personList.getItem(s).value);
          }

      }
      return Promise.resolve("");
  }

  getPathsAtt(str1,str2){
      this.personList.splice(0);

      var rows = this.database.executeQuery(this.viewName);
      for(var i in rows) {
          if(rows.hasOwnProperty(i)) {
              this.personList.push(rows[i]);
          }
      }
      var arr = [];
      for ( var s =0; s< this.personList.length; s++){

          if(this.personList.getItem(s).id.startsWith(str1)){
              arr.push( this.personList.getItem(s).value.replace(str2,""));
          }

      }
      return arr;
  }
  deleteStart(str){
      this.personList.splice(0);

      var rows = this.database.executeQuery(this.viewName);
      for(var i in rows) {
          if(rows.hasOwnProperty(i)) {
              this.personList.push(rows[i]);
          }
      }
      for ( var s =0; s< this.personList.length; s++){

          if(this.personList.getItem(s).id.startsWith(str)){
              console.log(this.database.getDocument(this.personList.getItem(s)._id));
              this.database.deleteDocument(this.personList.getItem(s)._id);
          }

      }

  }
  delete(id){

      this.personList.splice(0);

      var rows = this.database.executeQuery(this.viewName);
      for(var i in rows) {
          if(rows.hasOwnProperty(i)) {
              this.personList.push(rows[i]);
          }
      }
      for ( var s =0; s< this.personList.length; s++){

          if(this.personList.getItem(s).id===id){
              console.log(this.database.getDocument(this.personList.getItem(s)._id));
             this.database.deleteDocument(this.personList.getItem(s)._id);
          }

      }


  }
    add(id, value){
        this.delete(id);
       var doc = this.database.createDocument({
            "id": id,
            "value": value
        });

    }

    print(){

        this.personList.splice(0);

        var rows = this.database.executeQuery(this.viewName);
        
        for(var i in rows) {
            if(rows.hasOwnProperty(i)) {
                this.personList.push(rows[i]);

            }
        }


        for ( var s =0; s< this.personList.length; s++){
            console.log(s +" : "+this.personList.getItem(s).id +"  "+ this.personList.getItem(s).value);
        }
    }
}

module.exports = Database;



function indexOfObjectId(needle, haystack) {
    for(var i = 0; i < haystack.length; i++) {
    if(haystack.getItem(i) != undefined && haystack.getItem(i).hasOwnProperty("_id")) {
        if(haystack.getItem(i)._id == needle) {
            return i;
        }
    }
}
return -1;
}

