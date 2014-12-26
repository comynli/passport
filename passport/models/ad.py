import copy
import crypt
import base64
import logging
import ldap
import ldap.modlist as modlist
from collections import namedtuple
from ..utils import random_str

__author__ = 'comyn'


_User = namedtuple('_User', ['uid', 'name', 'primary_group', 'groups', 'roles', 'mail', 'phone', 'secret'])

_Group = namedtuple('_Group', ['gid', 'name', 'members'])

_Application = namedtuple('_Application', ['name', 'permissions', 'description'])

_Permission = namedtuple('_Permission', ['name', 'roles'])


def dump(o):
    if isinstance(o, Model):
        ret = dict()
        for f in o.fields:
            ret[f] = dump(getattr(o, f))
        return ret
    if isinstance(o, list):
        ret = list()
        for item in o:
            ret.append(dump(item))
        return ret
    return o


class Model(object):
    app = None
    db = None
    logger = None

    @classmethod
    def init_app(cls, app):
        cls.app = app
        cls.db = ldap.initialize(app.config.read('/passport/ldap/uri').value)
        cls.db.bind_s(app.config.read('/passport/ldap/admin').value,
                      app.config.read('/passport/ldap/password').value)
        cls.logger = logging

    @classmethod
    def config(cls, key):
        return cls.app.config.read(key).value

    @property
    def fields(self):
        if hasattr(self, '_fields'):
            return self._fields
        return []

    def dump(self):
        return dump(self)


class User(_User, Model):
    @classmethod
    def get(cls, dn):
        _get_option = lambda x: x.split(":")[1]
        try:
            _, entry = cls.db.search_s(dn, ldap.SCOPE_BASE)[0]
            uid = int(entry['uidNumber'][0])
            name = entry['cn'][0]
            roles = [_get_option(o) for o in entry.get('o', list()) if o.startswith('role:')]
            mail = [_get_option(o) for o in entry.get('o', list()) if o.startswith('mail:')]
            phone = [_get_option(o) for o in entry.get('o', list()) if o.startswith('phone:')]
            try:
                secret = [_get_option(o) for o in entry.get('o', list()) if o.startswith('secret:')][0]
            except Exception as e:
                cls.logger.warn(e)
                secret = None
            groups = []
            primary_group = None
            for pg in cls.db.search_s('ou=Group,%s' % cls.config('/passport/ldap/root_dn'),
                                     ldap.SCOPE_ONELEVEL,
                                     '(gidNumber=%s)' % entry['gidNumber'][0]):
                primary_group = Group.get(pg[0])
            for g in cls.db.search_s('ou=Group,%s' % cls.config('/passport/ldap/root_dn'),
                                     ldap.SCOPE_ONELEVEL,
                                     '(memberUid=%s)' % name):
                groups.append(Group.get(g[0]))
            return User(uid, name, primary_group, groups, roles, mail, phone, secret)
        except ldap.NO_SUCH_OBJECT:
            pass
        except Exception as e:
            cls.logger.error("get user<%s> fail %s" % (dn, e))

    def new_attribute(self, attr, value):
        dn = 'uid=%s,ou=People,%s' % (self.name, self.config('/passport/ldap/root_dn'))
        try:
            _, entry = self.db.search_s(dn, ldap.SCOPE_BASE)[0]
            old_entry = copy.deepcopy(entry)
            if entry.get('o') is None:
                entry['o'] = list()
            entry['o'].append(str("%s:%s" % (attr, value)))
            ldif = modlist.modifyModlist(old_entry, entry)
            self.db.modify_s(dn, ldif)
            return True
        except Exception as e:
            self.logger.error("add attribute %s:%s fail %s" % (attr, value, e))
            return False

    def update_attribute(self, attr, old_value, value):
        dn = 'uid=%s,ou=People,%s' % (self.name, self.config('/passport/ldap/root_dn'))
        try:
            _, entry = self.db.search_s(dn, ldap.SCOPE_BASE)[0]
            old_entry = copy.deepcopy(entry)
            if entry.get('o') is None:
                entry['o'] = list()
            try:
                entry['o'].remove('%s:%s' % (attr, old_value))
            except ValueError:
                pass
            entry['o'].append("%s:%s" % (attr, value))
            ldif = modlist.modifyModlist(old_entry, entry)
            self.db.modify_s(dn, ldif)
            return True
        except Exception as e:
            self.logger.error("update attribute %s:%s to %s:%s fail %s" % (attr, old_value, attr, value, e))
            return False

    def gen_secret(self):
        with open("/dev/urandom") as f:
            secret = base64.b32encode(f.read(80))[:16]
            if self.secret is None:
                self.new_attribute('secret', secret)
            else:
                self.update_attribute('secret', self.secret, secret)
            return secret

    def change_passwd(self, passwd):
        insalt = '$6$%s$' % random_str(8)
        hased = crypt.crypt(passwd, insalt)
        dn = 'uid=%s,ou=People,%s' % (self.name, self.config('/passport/ldap/root_dn'))
        try:
            _, entry = self.db.search_s(dn, ldap.SCOPE_BASE)[0]
            old_entry = copy.deepcopy(entry)
            entry['userPassword'] = '{crypt}%s' % hased
            ldif = modlist.modifyModlist(old_entry, entry)
            self.db.modify_s(dn, ldif)
            return True
        except Exception as e:
            self.logger.error("change password for %s fail %s" % (self.name, e))
            return False


class Group(_Group, Model):
    @classmethod
    def get(cls, dn):
        _, entry = cls.db.search_s(dn, ldap.SCOPE_BASE)[0]
        gid = int(entry['gidNumber'][0])
        name = entry['cn'][0]
        members = entry.get('memberUid', list())
        # for m in entry.get('memberUid', list()):
        #     q = 'uid=%s,ou=People,%s' % (m, cls.config('/passport/ldap/root_dn'))
        #     user = User.get(q)
        #     if user:
        #         members.append(user)
        return Group(gid, name, members)


class Application(_Application, Model):
    @classmethod
    def get(cls, name):
        dn = 'ou=%s,ou=Application,%s' % (name, cls.config('/passport/ldap/root_dn'))
        try:
            _, info = cls.db.search_s(dn, ldap.SCOPE_BASE)[0]
            desc = info.get('description', ['', ])[0]
            permissions = list()
            for p, _ in cls.db.search_s(dn, ldap.SCOPE_ONELEVEL):
                permissions.append(Permission.get(p))
            return Application(name, permissions, desc)
        except ldap.NO_SUCH_OBJECT:
            return
        except Exception as e:
            cls.logger.error("get application<%s> fail %s" % (name, e))
            return


class Permission(_Permission, Model):
    @classmethod
    def get(cls, dn):
        try:
            _, entry = cls.db.search_s(dn, ldap.SCOPE_BASE)[0]
            name = entry['cn'][0]
            roles = entry.get('o', list())
            return Permission(name, roles)
        except ldap.NO_SUCH_OBJECT:
            pass
        except Exception as e:
            cls.logger.error("get permission<%s> fail %s" % (dn, e))