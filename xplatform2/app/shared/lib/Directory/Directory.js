
const Node  = require("./Node");
class Directory {

    constructor() {
        this.root = new Node();

        console.log(this.root)
    }

    add(str){
        var paths = str.split("/");

        console.log("CONSTRUCTOR : " +this.root);

        var temp = this.root;
        while(paths.length!==0){
            console.log(paths[0]);
            var index = -1 ;
            for(var i =0; i< temp.children.length ; i++){
                if(temp.children[i].name == paths[0]){
                    index  = i;
                    break;
                }
            }
            if(index == -1){
                var n = new Node ();
                n.name = paths[0];
                n.parent = temp;
                temp.children.push(n);
                temp = n;
            }
            else {
                temp = temp.children[index];
            }

            paths.reverse();
            paths.pop();
            paths.reverse();
        }
        console.log(this.root);


        return Promise.resolve();
        }
    write(path, str){
        this.add(path);

        var paths = path.split("/");

        var temp = this.root;

        while(paths.length!==0){

            var index;
            for(var i =0; i< temp.children.length ; i++){
                if(temp.children[i].name == paths[0]){
                    index  = i;
                    break;
                }
            }
            temp = temp.children[index];
            paths.reverse();
            paths.pop();
            paths.reverse();
        }
        temp.text = str;

        return Promise.resolve();
    }
    read(path){
        this.add(path);

        var paths = path.split("/");

        var temp = this.root;

        while(paths.length!==0){

            var index;
            for(var i =0; i< temp.children.length ; i++){
                if(temp.children[i].name == paths[0]){
                    index  = i;
                    break;
                }
            }
            temp = temp.children[index];
            paths.reverse();
            paths.pop();
            paths.reverse();
        }

        return Promise.resolve(temp.text);
    }
    deleteFile(path){
        this.add(path);

        var paths = path.split("/");

        var temp = this.root;

        while(paths.length!==0){

            var index;
            for(var i =0; i< temp.children.length ; i++){
                if(temp.children[i].name == paths[0]){
                    index  = i;
                    break;
                }
            }
            temp = temp.children[index];
            paths.reverse();
            paths.pop();
            paths.reverse();
        }
        temp.parent.children.splice(index,1);
        temp.parent ="";
        return Promise.resolve();
    }

    getFolders(path){
        var paths = path.split("/");

        var temp = this.root;

        while(paths.length!==0){

            var index;
            for(var i =0; i< temp.children.length ; i++){
                if(temp.children[i].name == paths[0]){
                    index  = i;
                    break;
                }
            }
            temp = temp.children[index];
            paths.reverse();
            paths.pop();
            paths.reverse();
        }
    return temp.children;
    }
    doesExist(){


    }





}


module.exports = new Directory();