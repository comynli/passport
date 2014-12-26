import logging
import etcd
import redis
import tornado.web
from .models import ad
from .models import db


__author__ = 'comyn'


class App(tornado.web.Application):
    def __init__(self, handlers, **settings):
        self.config = etcd.Client(settings.get('etc_host', '127.0.0.1'), int(settings.get('etc_port', 4001)))
        self.cache = redis.from_url(self.config.read('/passport/cache/uri').value,
                                    max_connections=int(self.config.read('/passport/cache/pool_size').value))
        settings['login_url'] = "/login"
        super(App, self).__init__(handlers, **settings)

    def create_all(self):
        db.Session.init_app(self)
        db.Session.instance().create_all()

    def drop_all(self):
        db.Session.init_app(self)
        db.Session.instance().drop_all()


class BaseHandler(tornado.web.RequestHandler):
    def initialize(self):
        ad.Model.init_app(self.application)
        db.Session.init_app(self.application)

    @property
    def session(self):
        return db.Session.instance().get()

    @property
    def cache(self):
        return self.application.cache

    def config(self, key, default=None):
        try:
            return self.application.config.read(key).value
        except Exception as e:
            return default

    @property
    def logger(self):
        return logging

    def get_user(self, uid):
        dn = 'uid=%s,ou=People,%s' % (uid, self.config('/passport/ldap/root_dn'))
        return ad.User.get(dn)

    def get_current_user(self):
        token = self.get_argument('_token')
        if token:
            uid = self.cache.get('%s::token::%s' % (self.config('/passport/cache/prefix'), token))
            return self.get_user(uid)