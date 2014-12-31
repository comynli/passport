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

_Application = namedtuple('_Application', ['name', 'key', 'address', 'permissions', 'description'])

_Permission = namedtuple('_Permission', ['name', 'application', 'roles', 'description'])


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
    def _pack(cls, entry):
        _get_option = lambda x: x.split(":")[1]
        uid = int(entry['uidNumber'][0])
        name = entry['cn'][0]
        roles = entry.get("ou")
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

    @classmethod
    def get(cls, dn):
        try:
            _, entry = cls.db.search_s(dn, ldap.SCOPE_BASE)[0]
            return cls._pack(entry)
        except ldap.NO_SUCH_OBJECT:
            pass
        except Exception as e:
            cls.logger.error("get user<%s> fail %s" % (dn, e))

    @classmethod
    def get_all(cls):
        ret = list()
        dn = 'ou=People,%s' % cls.config('/passport/ldap/root_dn')
        try:
            for _, entry in cls.db.search_s(dn, ldap.SCOPE_ONELEVEL):
                u = cls._pack(entry)
                if u:
                    ret.append(u)
        except Exception as e:
            cls.logger.error(e)
        return ret

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

    def delete_attribute(self, attr, value):
        dn = 'uid=%s,ou=People,%s' % (self.name, self.config('/passport/ldap/root_dn'))
        try:
            _, entry = self.db.search_s(dn, ldap.SCOPE_BASE)[0]
            old_entry = copy.deepcopy(entry)
            attrs = entry.get("o", list())
            attrs.remove('%s:%s' % (attr, value))
            entry['o'] = attrs
            ldif = modlist.modifyModlist(old_entry, entry)
            self.db.modify_s(dn, ldif)
            return True
        except Exception as e:
            self.logger.error("delete attribute %s:%s fail %s" % (attr, value, e))
            return False

    @classmethod
    def _get_max_uid(cls):
        uids = [int(x['uidNumber'][0]) for _, x in cls.db.search_s('ou=People,%s' % cls.config('/passport/ldap/root_dn'),
                               ldap.SCOPE_ONELEVEL, attrlist=['uidNumber'])]
        if len(uids) <= 0:
            return 9999
        uids.sort(reverse=True)
        return uids[0]

    @classmethod
    def new(cls, name, primary_group):
        group = Group.get('cn=%s,ou=Group,%s' % (primary_group, cls.config('/passport/ldap/root_dn')))
        if not group:
            return False, "primary group not found"
        dn = 'uid=%s,ou=People,%s' % (name, cls.config('/passport/ldap/root_dn'))
        entry = dict()
        entry['objectClass'] = ['account', 'posixAccount', 'top', 'shadowAccount']
        entry['gidNumber'] = group.gid
        entry['cn'] = [name, ]
        entry['homeDirectory'] = ['/home/%s' % name, ]
        entry['loginShell'] = ['/bin/bash']
        entry['uid'] = [name, ]
        entry['uidNumber'] = [cls._get_max_uid() + 1]
        ldif = modlist.addModlist(entry)
        cls.db.add_s(dn, ldif)
        return cls.get(dn)

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
        hashed = crypt.crypt(passwd, insalt)
        dn = 'uid=%s,ou=People,%s' % (self.name, self.config('/passport/ldap/root_dn'))
        try:
            _, entry = self.db.search_s(dn, ldap.SCOPE_BASE)[0]
            old_entry = copy.deepcopy(entry)
            entry['userPassword'] = '{crypt}%s' % hashed
            ldif = modlist.modifyModlist(old_entry, entry)
            self.db.modify_s(dn, ldif)
            return True
        except Exception as e:
            self.logger.error("change password for %s fail %s" % (self.name, e))
            return False

    def assign_role(self, role):
        dn = 'uid=%s,ou=People,%s' % (self.name, self.config('/passport/ldap/root_dn'))
        try:
            _, entry = self.db.search_s(dn, ldap.SCOPE_BASE)[0]
            old_entry = copy.deepcopy(entry)
            if entry.get('ou') is None:
                entry['ou '] = list()
            entry['ou'].append(role)
            ldif = modlist.modifyModlist(old_entry, entry)
            self.db.modify_s(dn, ldif)
            return True
        except Exception as e:
            self.logger.error("assign role %s to %s fail %s" % (role, self.name, e))
            return False

    def revoke_role(self, role):
        dn = 'uid=%s,ou=People,%s' % (self.name, self.config('/passport/ldap/root_dn'))
        try:
            _, entry = self.db.search_s(dn, ldap.SCOPE_BASE)[0]
            old_entry = copy.deepcopy(entry)
            entry['ou'].remove(role)
            ldif = modlist.modifyModlist(old_entry, entry)
            self.db.modify_s(dn, ldif)
            return True
        except Exception as e:
            self.logger.error("assign role %s to %s fail %s" % (role, self.name, e))
            return False

    def permissions(self, app):
        perms = set()
        application = Application.get(app)
        if not application:
            return perms
        for p in application.permissions:
            if len(set(p.roles).intersection(self.roles)) > 0:
                perms.add(p.name)
        return perms


class Group(_Group, Model):
    @classmethod
    def get(cls, dn):
        _, entry = cls.db.search_s(dn, ldap.SCOPE_BASE)[0]
        gid = int(entry['gidNumber'][0])
        name = entry['cn'][0]
        members = entry.get('memberUid', list())
        return Group(gid, name, members)

    @classmethod
    def _get_max_gid(cls):
        gids = [int(x['gidNumber'][0]) for _, x in
                cls.db.search_s('ou=Group,%s' % cls.config('/passport/ldap/root_dn'),
                                ldap.SCOPE_ONELEVEL, attrlist=['gidNumber'])]
        if len(gids) <= 0:
            return 9999
        gids.sort(reverse=True)
        return gids[0]

    @classmethod
    def new(cls, name):
        dn = 'cn=%s,ou=Group,%s' % (name, cls.config('/passport/ldap/root_dn'))
        entry = dict()
        entry['objectClass'] = ['posixGroup', 'top']
        entry['cn'] = [name, ]
        entry['gidNumber'] = [cls._get_max_gid() + 1, ]
        ldif = modlist.addModlist(entry)
        cls.db.add_s(dn, ldif)
        return cls.get(dn)

    def add_member(self, name):
        dn = 'cn=%s,ou=Group,%s' % (self.name, self.config('/passport/ldap/root_dn'))
        try:
            _, entry = self.db.search_s(dn, ldap.SCOPE_BASE)[0]
            old_entry = copy.deepcopy(entry)
            if entry.get('memberUid') is None:
                entry['memberUid'] = list()
            entry['memberUid'].append(name)
            ldif = modlist.modifyModlist(old_entry, entry)
            self.db.modify_s(dn, ldif)
            return True
        except Exception as e:
            self.logger.error('add member %s to %s fail %s' % (name, self.name, e))
            return False

    def delete_member(self, name):
        dn = 'cn=%s,ou=Group,%s' % (self.name, self.config('/passport/ldap/root_dn'))
        try:
            _, entry = self.db.search_s(dn, ldap.SCOPE_BASE)[0]
            old_entry = copy.deepcopy(entry)
            members = entry.get('memberUid', list())
            members.remove(name)
            ldif = modlist.modifyModlist(old_entry, entry)
            self.db.modify_s(dn, ldif)
            return True
        except Exception as e:
            self.logger.error('remove member %s from %s fail %s' % (name, self.name, e))
            return False


class Application(_Application, Model):
    @classmethod
    def get(cls, name):
        dn = 'ou=%s,ou=Application,%s' % (name, cls.config('/passport/ldap/root_dn'))
        try:
            _, info = cls.db.search_s(dn, ldap.SCOPE_BASE)[0]
            desc = info.get('description', ['', ])[0]
            key = info.get('st')[0]
            address = info.get('l', [])
            permissions = list()
            for p, _ in cls.db.search_s(dn, ldap.SCOPE_ONELEVEL):
                permissions.append(Permission.get(p))
            return Application(name, key, address, permissions, desc)
        except ldap.NO_SUCH_OBJECT:
            return
        except Exception as e:
            cls.logger.error("get application<%s> fail %s" % (name, e))
            return

    @classmethod
    def new(cls, name, desc=None):
        dn = 'ou=%s,ou=Application,%s' % (name, cls.config('/passport/ldap/root_dn'))
        entry = dict()
        entry['objectClass'] = ['organizationalUnit', 'top']
        entry['ou'] = [name, ]
        with open('/dev/urandom') as f:
            entry['st'] = [base64.b32encode(f.read(10))]
        if desc:
            entry['description'] = [desc, ]
        ldif = modlist.addModlist(entry)
        cls.db.add_s(dn, ldif)
        return cls.get(name)

    def add_permission(self, name, desc=None):
        dn = 'cn=%s,ou=%s,ou=Application,%s' % (name, self.name, self.config('/passport/ldap/root_dn'))
        entry = dict()
        entry['objectClass'] = ['top', 'applicationProcess']
        entry['cn'] = [name, ]
        if desc:
            entry['description'] = [desc, ]
        ldif = modlist.addModlist(entry)
        self.db.add_s(dn, ldif)
        self.permissions.append(Permission.get(dn))

    def delete_permission(self, name):
        dn = 'cn=%s,ou=%s,ou=Application,%s' % (name, self.name, self.config('/passport/ldap/root_dn'))
        self.db.delete_s(dn)


class Permission(_Permission, Model):
    @classmethod
    def get(cls, dn):
        try:
            _, entry = cls.db.search_s(dn, ldap.SCOPE_BASE)[0]
            name = entry['cn'][0]
            application = dn.split(',')[1].split('=')[1].strip()
            roles = entry.get('ou', list())
            desc = entry.get('description')
            return Permission(name, application, roles, desc)
        except ldap.NO_SUCH_OBJECT:
            pass
        except Exception as e:
            cls.logger.error("get permission<%s> fail %s" % (dn, e))

    def assign_role(self, role):
        dn = 'cn=%s,ou=%s,ou=Application,%s' % (self.name, self.application, self.config('/passport/ldap/root_dn'))
        try:
            _, entry = self.db.search_s(dn, ldap.SCOPE_BASE)[0]
            old_entry = copy.deepcopy(entry)
            if entry.get('ou') is None:
                entry['ou'] = list()
            entry['ou'].append(role)
            ldif = modlist.modifyModlist(old_entry, entry)
            self.db.modify_s(ldif)
        except Exception as e:
            self.logger.error('assign role %s to %s::%s fail %s' % (role, self.application, self.name, e))
            return False

    def revoke_role(self, role):
        dn = 'cn=%s,ou=%s,ou=Application,%s' % (self.name, self.application, self.config('/passport/ldap/root_dn'))
        try:
            _, entry = self.db.search_s(dn, ldap.SCOPE_BASE)[0]
            old_entry = copy.deepcopy(entry)
            roles = entry.get('ou', list())
            roles.remove(role)
            entry['ou'] = roles
            ldif = modlist.modifyModlist(old_entry, entry)
            self.db.modify_s(ldif)
        except Exception as e:
            self.logger.error('assign role %s to %s::%s fail %s' % (role, self.application, self.name, e))
            return False