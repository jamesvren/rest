#!/usr/bin/python3
# -*- coding: utf-8 -*-
import asyncio
import pickle
from testbase import LOG, module_dep

class ResourceDB():
    objs = {}

    @classmethod
    def insert(cls, obj):
        tid = asyncio.current_task().get_name()
        db = cls.objs.get(tid)
        if db:
            db.append(obj)
        else:
            cls.objs[tid] = [obj]
        LOG('debug', 'db', f'  Save resource {obj.type}:{obj.name}:{obj.id} to DB({tid}).')

    @classmethod
    def remove(cls, obj):
        tid = asyncio.current_task().get_name()
        db = cls.objs.get(tid, [])
        if db:
            try:
                db.remove(obj)
            except ValueError as e:
                LOG('error', 'db', f'Error: {obj}, {str(e)}')

    @classmethod
    async def __clear_from_db(cls, tid, db):
        for obj in db[::-1]:
            LOG('debug', 'db', f'  Clear {obj.type}\t-> {obj.name}:{obj.id} from DB({tid})')
            try:
                res = await obj.delete()
                retry = 1
                while res is None and retry == 0:
                    retry -= 1
                    asyncio.sleep(1)
                    res = await obj.delete()
            except Exception as e:
                if 'Not Found' in str(e):
                    pass
        # empty list of db
        db.clear()

    @classmethod
    async def clear(cls):
        tid = asyncio.current_task().get_name()
        db = cls.objs.get(tid, [])
        await cls.__clear_from_db(tid, db)

    @classmethod
    async def clearall(cls):
        LOG('info', 'db', '  To clear all DBs ...')
        i = 0
        tasks = set()
        for tid, db in cls.objs.items():
            _task = asyncio.create_task(cls.__clear_from_db(tid, db), name=tid)
            _task.add_done_callback(tasks.discard)
            tasks.add(_task)
            i += 1
            if i >= 30:
                await asyncio.gather(*tasks)
                i = 0
        if i > 0:
            await asyncio.gather(*tasks)
        cls.objs = {}

    @classmethod
    def dump(cls, detail=False):
        for db in cls.objs.values():
            for obj in db:
                LOG('info', 'db', f'  [cached] {obj.type}\t-> {obj.name}:{obj.id}')
                if detail:
                    LOG('info', 'db', obj.body)

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

