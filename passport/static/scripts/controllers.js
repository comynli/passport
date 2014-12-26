/**
 * Created by comyn on 14-12-23.
 */

var passportControllers = angular.module('passportControllers', []);

passportControllers.controller('LoginCtrl', ['$scope', '$http', '$location', 'Auth',
    function($scope, $http, $location, Auth){
        $scope.title = 'Login';
        $scope.login = function(){
            Auth.login($scope.username, $scope.password).then(
                function(token){
                    Auth.setToken(token);
                    $location.path("/");
                },
                function (msg) {
                    $scope.error = msg;
                }
            )
        }
    }]);


passportControllers.controller('ProfileCtrl', ['$scope', 'Profile',
    function($scope, Profile) {
        Profile.get(function(res){
            $scope.user = res.user;
        });
    }
]);

