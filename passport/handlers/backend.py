import json
import base64
import hashlib
from ..app import BaseHandler
from ..models import ad
from ..decorators import PermissionCheck

__author__ = 'comyn'


class UserInfoHandler(BaseHandler):
    def get(self, *args, **kwargs):
        try:
            args = json.loads(self.request.body)
            application = ad.Application.get(args['app'])
            token = args['token']
            secret = args['secret']
        except Exception as e:
            self.logger.error(e)
            self.write({'status': 400, 'msg': 'invalidate arguments'})
            return
        if hashlib.sha256('%s%s%s' % (application.name, token, application.key)).hexdigest() != secret:
            self.write({'status': 401, 'msg': 'illegal application'})
            return
        uid = self.cache.get('%s::token::%s' % (self.config('/passport/cache/prefix'), token))
        user = self.get_user(uid)
        if user:
            user.secret = None
            self.write({'status': 200, 'user': user.dump(), 'permissions': user.permissions(application.name)})
        else:
            self.write({'status': 404, 'msg': 'user no found'})


class UserManageHandler(BaseHandler):
    @PermissionCheck('users.list', 'users.manage')
    def get(self, *args, **kwargs):
        users = [x.dump() for x in ad.User.get_all()]
        self.write({'status': 200, 'users': users})

    @PermissionCheck('users.add', 'users.manage')
    def put(self, *args, **kwargs):
        try:
            args = json.loads(self.request.body)
            name = args['name']
            primary_group = args['primary_group']
            roles = args.get('roles', list())
            mail = args.get('mail', list())
            phone = args.get('phone', list())
        except Exception as e:
            self.logger.error(e)
            self.write({'status': 400, 'msg': 'invalidate arguments'})
            return
        try:
            user = ad.User.new(name, primary_group)
            secret = user.gen_secret()
            with open("/dev/urandom") as f:
                password = base64.b32encode(f.read(80))[:16]
            user.change_passwd(password)
        except Exception as e:
            self.write({"status": 500, "msg": 'create new user %s fail %s' % (name, e)})
            return
        for role in roles:
            user.assign_role(role)
        for p in phone:
            user.new_attribute('phone', p)
        for m in mail:
            user.new_attribute('mail', m)
        self.write({'status': 200, "secret": secret, "password": password})