/**
 * Created by comyn on 14-12-24.
 */


var passportServices = angular.module('passportServices', ['ngResource']);

passportServices.factory('Auth', ['$http', '$q',
    function ($http, $q) {
        return {
            login: function (username, password) {
                var deferred = $q.defer();
                $http.post("/account/login", {username: username, password:password, app:"passport"}, {async:false}).
                    success(function(data){
                        if(data.status == 200){
                            deferred.resolve(data);
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
            },
            setPermissions: function(perms){
                window.sessionStorage.setItem('_permissions', JSON.stringify(perms))
            },
            setUser: function(u){
                window.sessionStorage.setItem('_user', JSON.stringify(u));
            },
            getToken: function () {
                return window.localStorage.getItem('_token');
            },
            hasPermissions: function(perm){
                var permissions = JSON.parse(window.sessionStorage.getItem('_permissions'));
                return _.some(permissions, function(item) {
                    if(_.isString(item))
                        return item.trim() === perm.trim();
                });
            },
            isLogged: function () {
                var token = window.localStorage.getItem('_token');
                var deferred = $q.defer();
                if (token){
                    $http.head("/account/login", {params:{_token:token}}).
                        success(function(data, status, header){
                            if(header('X-Passport-LoggedIn')){
                                deferred.resolve(true);
                            }else{
                                deferred.resolve(false);
                            }
                        }).
                        error(function(){
                            deferred.resolve(false);
                        })
                }else{
                    deferred.resolve(false);
                }
                return deferred.promise;
            },
            logout: function () {
                var token = window.localStorage.getItem('_item');
                if (token){
                    $http.delete("/account/login", {params:{_token:token}})
                }
                window.localStorage.removeItem('_token');
                window.sessionStorage.removeItem('_permissions');
                window.sessionStorage.removeItem('_user');
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