
class Node{

    constructor (){
        this.children = [];
        this.parent = "";
        this.text = "";
        this.name = "";
    }

    addChildren(elt ){
        if(this.text!="") {
            this.children.push(elt);
        }
        else{
            console.log("Cannot add a child to  a  text file")
        }
    }
    getChildren(){
        return this.children;
    }
    getText(){
        return this.text;
    }
    addText(txt){
        this.text = txt;
    }
    print(){
      var  temp = this;
        var stack = [];
        stack.push(temp.name);
     while(temp.parent!==""){
         stack.push(temp.parent.name);
     }
     var str = "";
     while(stack.length!==1){
         str+= stack.pop()+"/";
     }

     console.log(str +" : "+ this.text );
    }


}

module.exports = Node;