#!/usr/bin/python3
# -*- coding: utf-8 -*-
import gevent
import pickle
from testbase import DEBUG

class ResourceDB():
    objs = {}

    @classmethod
    def insert(cls, obj):
        tid = id(gevent.getcurrent())
        db = cls.objs.get(tid)
        if db:
            db.append(obj)
        else:
            cls.objs[tid] = [obj]
        DEBUG('db', f'  Save resource {obj.type}:{obj.name}:{obj.id} to DB({tid}).')

    @classmethod
    def remove(cls, obj):
        tid = id(gevent.getcurrent())
        db = cls.objs.get(tid, [])
        if db:
            try:
                db.remove(obj)
            except ValueError as e:
                print(f'Error: {obj}, {str(e)}')

    @classmethod
    def __clear_from_db(cls, db):
        for obj in db[::-1]:
            DEBUG('db', f'  Clear {obj.type} -> {obj.name}:{obj.id}')
            res = obj.delete()
            retry = 1
            while res is None and retry == 0:
                retry -= 1
                time.sleep(1)
                res = obj.delete()
        db.clear()

    @classmethod
    def clear(cls):
        tid = id(gevent.getcurrent())
        db = cls.objs.get(tid, [])
        cls.__clear_from_db(db)

    @classmethod
    def clearall(cls):
        DEBUG('db', '  To clear all DBs ...')
        for db in cls.objs.values():
            cls.__clear_from_db(db)

    @classmethod
    def dump(cls):
        for db in cls.objs.values():
            for obj in db:
                print(f'  [cached] {obj.type} -> {obj.name}:{obj.id}')

    @classmethod
    def flush(cls):
        with open('res.db', 'wb') as f:
            pickle.dump(cls.objs, f)

    @classmethod
    def load(cls):
        try:
            with open('res.db', 'rb') as f:
                cls.objs = pickle.load(f)
            cls.dump()
        except FileNotFoundError as e:
            pass

