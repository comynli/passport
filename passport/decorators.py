import functools

__author__ = 'comyn'


class PermissionCheck(object):
    def __init__(self, *permissions):
        self.permissions = permissions

    def __call__(self, func):
        @functools.wraps(func)
        def decorated(instance, *args, **kwargs):
            if len(instance.get_current_user().permissions(instance.application.name).intersection(set(self.permissions))) > 0:
                func(instance, *args, **kwargs)
            else:
                instance.write({'status': 401, 'msg': 'permissions deny'})
        return decorated
