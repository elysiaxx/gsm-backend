from abc import ABC, abstractmethod
from app.app import mongodb


class Document(mongodb.Document):
    """
    Class entity is parent class for all other class
    """
    __abstract__ = True
    meta = {
        "allow_inheritance": True
    }