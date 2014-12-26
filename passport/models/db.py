from sqlalchemy import create_engine, Column
from sqlalchemy.orm import sessionmaker
from sqlalchemy.types import Integer, String, CHAR, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base

__author__ = 'comyn'

Model = declarative_base()


class Session(object):
    app = None

    def __init__(self, engine):
        self._session = sessionmaker(bind=engine)()
        self.engine = engine

    def create_all(self):
        Model.metadata.create_all(self.engine)

    def drop_all(self):
        Model.metadata.drop_all(self.engine)

    @classmethod
    def init_app(cls, app):
        cls.app = app

    @classmethod
    def config(cls, key, default=None):
        try:
            return cls.app.config.read(key).value
        except Exception as e:
            return default

    @classmethod
    def instance(cls):
        if not hasattr(cls, '_instance'):
            engine = create_engine(cls.config('/passport/db/uri'),
                                   pool_size=int(cls.config('/passport/db/pool_size', 30)),
                                   pool_recycle=int(cls.config('/passport/db/pool_recycle', 3600)),
                                   echo=True)
            cls._instance = cls(engine)
        return cls._instance

    def get(self):
        return self._session


class Audit(Model):
    __tablename__ = 'audit'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), nullable=False, index=True)
    session_id = Column(CHAR(32), unique=True, nullable=False)
    start = Column(DateTime, nullable=False)
    end = Column(DateTime, nullable=True)
    app = Column(String(128), nullable=False)
    target = Column(String(128), nullable=True)
    success = Column(Boolean, nullable=False)

