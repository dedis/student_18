const observableModule = require("data/observable");

/* ***********************************************************
 * Keep data that is displayed in your app drawer in the MyDrawer custom component view model.
 *************************************************************/
function MyDrawerViewModel(selectedPage) {
  const   viewModel = observableModule.fromObject({
        /* ***********************************************************
         * Use the MyDrawer view model to initialize the properties data values.
         * The navigationItems property is initialized here and is data bound to <ListView> in the MyDrawer view file.
         * Add, remove or edit navigationItems to change what is displayed in the app drawer list.
         *************************************************************/
        navigationItems: [{
                title: "Home",
                name: "home",
                route: "drawers/home/home-page",
                icon: "\uf015",
                isSelected: selectedPage === "Home"
            },
            {
                title: "PoP",
                name: "pop",
                route: "drawers/pop/pop-page",
                icon: "\uf0a1",
                isSelected: selectedPage === "PoP"
            },


            {
                title: "Settings",
                name: "settings",
                route: "drawers/settings/settings-page",
                icon: "\uf013",
                isSelected: selectedPage === "Settings"
            }
        ]
    });

    return viewModel;
}
/*
function addCisc(){
    viewModel.context.navigationItems.push( {
        title: "CISC",
        name: "cisc",
        route: "drawers/cisc/cisc-page",
        icon: "\uf0c1",
        isSelected: selectedPage === "CISC"
    });
}
function removeCisc(){
    viewModel.context.navigationItems.remove(viewModel.context.navigationItems.length-1,viewModel.context.navigationItems.length);
}
*/
module.exports = MyDrawerViewModel;
//module.exports.addCisc = addCisc;
//module.exports.removeCisc = removeCisc;