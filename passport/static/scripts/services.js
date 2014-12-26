/**
 * Created by comyn on 14-12-24.
 */


var passportServices = angular.module('passportServices', ['ngResource']);

passportServices.factory('Auth', ['$http', '$q',
    function ($http, $q) {
        var _token = null;
        return {
            login: function (username, password) {
                var deferred = $q.defer();
                $http.post("/account/login", {username: username, password:password, app:"passport"}, {async:false}).
                    success(function(data){
                        if(data.status == 200){
                            deferred.resolve(data.token);
                        }else{
                            deferred.reject(data.msg)
                        }
                    }).
                    error(function () {
                        deferred.reject('Internal Server Error')
                    });
                return deferred.promise;
            },
            setToken: function(token){
                window.localStorage.setItem('_token', token);
                _token = token;
            },
            getToken: function () {
                return window.localStorage.getItem('_token');
            },
            isLogged: function () {
                return window.localStorage.getItem('_token') != null;
            },
            logout: function () {
                window.localStorage.removeItem('_token');
            }
        }
    }

]);


passportServices.factory('Profile', ['$resource', 'Auth',
    function($resource, Auth) {
        return $resource('/account/profile', {_token: Auth.getToken()}, {
            get: {method:'GET'}
        });
    }

]);