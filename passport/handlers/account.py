import json
import ldap
import uuid
import urllib
import qrcode
import StringIO
import datetime
import tornado.web
from qrcode.image.svg import SvgImage
from ..app import BaseHandler
from ..models import ad, db
from ..utils import totp_verify

__author__ = 'comyn'


class LoginHandler(BaseHandler):
    def _commit_audit(self, audit, end='now', success=False):
        if end == 'now':
            end = datetime.datetime.now()
        audit.end = end
        audit.success = success
        self.session.add(audit)
        try:
            self.session.commit()
        except Exception as e:
            self.session.rollback()
            self.logger.error("save audit info fail %s" % e)
        finally:
            self.session.close()

    def post(self, *args, **kwargs):
        try:
            args = json.loads(self.request.body)
            username = args['username']
            application = args['app']
            if self.config('/passport/auth/totp') == 'true':
                password = args['password'][:-6]
                code = args['password'][-6:]
            else:
                password = args['password']
                code = ''
        except Exception as e:
            self.logger.error(e)
            self.write({'status': 400, 'msg': 'invalidate arguments'})
            return

        l = ldap.initialize(self.config('/passport/ldap/uri'))
        dn = 'uid=%s,ou=People,%s' % (username, self.config('/passport/ldap/root_dn'))
        token = uuid.uuid4().hex
        audit = db.Audit()
        audit.username = username
        audit.session_id = token
        audit.app = application
        audit.start = datetime.datetime.now()
        num = self.cache.incr('%s::try::%s' % (self.config('/passport/cache/prefix'), username))
        if num == 1:
            self.cache.expire('%s::try::%s' % (self.config('/passport/cache/prefix'), username), 15 * 60)
        if num > int(self.config('/passport/auth/max_try', 3)):
            self._commit_audit(audit)
            self.write({"status": 403, "msg": "too many attempts, unlock after %s seconds." %
                                              self.cache.ttl('%s::try::%s' %
                                                             (self.config('/passport/cache/prefix'), username))})
            return
        try:
            l.simple_bind_s(dn, password)
            user = ad.User.get(dn)
            if not user:
                self._commit_audit(audit)
                self.write({"status": 404, "msg": "user<%s> not exist" % username})
                return
            if self.config('/passport/auth/totp') == 'false' or totp_verify(user.secret, code):

                self.cache.set('%s::token::%s' % (self.config('/passport/cache/prefix'), token), user.name)
                self.cache.delete('%s::try::%s' % (self.config('/passport/cache/prefix'), username))
                self._commit_audit(audit, None, True)
                self.write({"status": 200, "token": token, "user": user.dump(),
                            "permissions": list(user.permissions(application))})
            else:
                self._commit_audit(audit)
                self.write({"status": 403, "msg": "dynamic password error"})
        except Exception as e:
            self.logger.error(e)
            self._commit_audit(audit)
            self.write({"status": 404, "msg": "password error or user<%s> not exist" % username})

    def put(self, *args, **kwargs):
        self.post()

    def head(self, *args, **kwargs):
        user = self.get_current_user()
        if user:
            self.add_header("X-Passport-LoggedIn", "true")

    def delete(self, *args, **kwargs):
        token = self.get_argument('_token')
        self.cache.delete('%s::token::%s' % (self.config('/passport/cache/prefix'), token))


class QRHandler(BaseHandler):
    def get(self, name, secret):
        label = urllib.quote('%s@passport' % name)
        content = 'otpauth://totp/%s?secret=%s' % (label, secret)
        qr = qrcode.QRCode()
        qr.add_data(content)
        img = qr.make_image(image_factory=SvgImage)
        stream = StringIO.StringIO()
        img.save(stream)
        self.add_header('content-type', 'image/svg+xml')
        self.write(stream.getvalue())


class ProfileHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self, *args, **kwargs):
        user = self.get_current_user()
        if not user:
            self.write({"status": 404, "msg": "not exist"})
        else:
            self.write({"status": 200, "user": user.dump()})

    @tornado.web.authenticated
    def put(self, *args, **kwargs):
        user = self.get_current_user()
        ret = {}
        try:
            args = json.loads(self.request.body)
            if 'refresh_secret' in args.keys():
                user.gen_secret()
                ret['secret'] = 'refreshed'
            if 'change_passwd' in args.keys():
                user.change_passwd(args['change_passwd'])
                ret['password'] = 'changed'
            if 'update' in args.keys():
                for item in args["update"]:
                    user.update_attribute(item['attr'], item['old_value'], item['value'])
                    if 'updated' not in ret.keys():
                        ret['updated'] = []
                    ret['updated'].append(item)
            if 'new' in args.keys():
                for item in args['new']:
                    user.new_attribute(item['attr'], item['value'])
                    if 'new' not in ret.keys():
                        ret['new'] = []
                    ret['new'].append(item)
            self.write({"status": 200, "result": ret})
        except Exception as e:
            self.logger.error("update profile of %s fail %s" % (user.name, e))
            self.write({"status": 500, "result": ret, "msg": "update profile fail"})