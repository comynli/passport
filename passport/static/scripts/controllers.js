/**
 * Created by comyn on 14-12-23.
 */

var passportControllers = angular.module('passportControllers', []);

passportControllers.controller('LoginCtrl', ['$scope', '$http', '$location', 'Auth',
    function($scope, $http, $location, Auth){
        $scope.login = function(){
            Auth.isLogged().then(
                function(isLoggedIn){
                    if(isLoggedIn){
                        $location.path("/")
                    }else{
                        Auth.login($scope.username, $scope.password).then(
                            function(data){
                                Auth.setToken(data.token);
                                Auth.setPermissions(data.permissions);
                                Auth.setUser(data.user);
                                $location.path("/");
                            },
                            function (msg) {
                                $scope.error = msg;
                            }
                        )
                    }
                },
                function(){
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
            );
        }
    }]);


passportControllers.controller('ProfileCtrl', ['$scope', 'Profile', 'Auth',
    function($scope, Profile, Auth) {
        Profile.get(function(res){
            $scope.user = res.user;
        });
    }
]);

