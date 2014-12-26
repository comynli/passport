import tornado.web

__author__ = 'comyn'


class StaticHandler(tornado.web.StaticFileHandler):
    def parse_url_path(self, url_path):
        if not url_path or url_path.endswith('/'):
            url_path += self.settings.get("index", "index.html")
        return super(StaticHandler, self).parse_url_path(url_path)
