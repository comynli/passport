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
run(['$rootScope', '$location', '$routeParams', 'Auth', function ($rootScope, $location, $routeParams, Auth) {
    $rootScope.$on("$routeChangeStart", function (event, next) {
        sessionStorage.setItem('_next', $location.path());
        Auth.isLogged().then(
            function(isLoggedIn){
                if ((!isLoggedIn || next.templateUrl === "template/login.html")){
                    $location.url("/login");
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


