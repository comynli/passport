/**
 * Created by comyn on 14-12-23.
 */

var passportApp = angular.module('passportApp', [
    'ngRoute',
    'passportControllers',
    'passportServices'
]);

passportApp.config(['$routeProvider',
    function ($routeProvider) {
        $routeProvider.
            when('/login', {
                templateUrl: 'template/login.html',
                controller: 'LoginCtrl'
            }).
            when("/", {
                templateUrl: 'template/profile.html',
                controller: 'ProfileCtrl'
            })
            .otherwise({
                redirectTo: "/"
            })
    }
]).
run(['$rootScope', '$location', 'Auth', function ($rootScope, $location, Auth) {
    $rootScope.$on("$routeChangeStart", function (event, next) {
        Auth.isLogged().then(
            function(isLoggedIn){
                if ((!isLoggedIn || next.templateUrl === "template/login.html")){
                    $location.path("/login");
                }
            },
            function(){}
        );
    });

   $rootScope.logout = function(){
       Auth.logout();
       $location.path('/login');
   }
}]);


