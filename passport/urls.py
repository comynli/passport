
import os
from tornado.web import url, RedirectHandler
from .handlers.account import LoginHandler, ProfileHandler, QRHandler
from .handlers.utils import StaticHandler

__author__ = 'comyn'

HANDLERS = [
    url(r"/", RedirectHandler, {"url": "/app/", "permanent": 301}),
    url(r"/login", RedirectHandler, {"url": "/app/#/login", "permanent": 301}),
    url(r"/app/(.*)", StaticHandler, {'path': os.path.join(os.path.dirname(__file__), "static")}),
    url(r"/account/login", LoginHandler),
    url(r"/account/profile", ProfileHandler),
    url(r"/qr/(?P<name>\w+)-(?P<secret>.*)\.svg", QRHandler)
]