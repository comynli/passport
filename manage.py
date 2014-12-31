#!/bin/env python
# coding=utf-8

import shlex
import click
import tornado.ioloop
import tornado.httpserver
from tornado.options import parse_command_line, options
from passport.app import App
from passport.urls import HANDLERS

__author__ = 'comyn'


app = App('passport', HANDLERS)
instance = tornado.ioloop.IOLoop.instance()


@click.group()
def manager():
    pass


@manager.command()
def setup():
    app.create_all()


@click.command()
def cleanup():
    app.drop_all()


@manager.command()
@click.option('--host', default='127.0.0.1', help="bind host")
@click.option('--port', default=7000, help='listen port')
@click.argument('args', required=False, nargs=-1)
def start(host, port, args=None):
    if args:
        _args = ['', ]
        _args.extend(args)
        parse_command_line(_args)
    http_server = tornado.httpserver.HTTPServer(app)
    http_server.listen(port=port, address=host)
    instance.start()


@manager.command()
def stop():
    instance.stop()


if __name__ == '__main__':
    manager()

