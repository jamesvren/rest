#!/usr/bin/python3
# -*- coding: utf-8 -*-

import asyncio
import argparse
import inspect
import time
import sys
import os
import signal
import re
from itertools import repeat
from resource import ResourceDB, pasrse_config_file
from testbase import LOG

tasks = set()
ctrl_c = False
key_times = 0
def key_ctrl_c(sig, frame):
    global key_times, ctrl_c
    ctrl_c = True
    key_times += 1
    LOG(msg=f'Please wait for last case finished ...(three times to break: {key_times} times)')
    if key_times >= 3:
        try:
            tasks = asyncio.all_tasks()
            for _task in tasks():
                _task.cancel()
        except:
            pass
        finally:
            LOG(msg='[**] Break by user. Please clear resource manually.')
            ResourceDB.dump()
            ResourceDB.flush()
signal.signal(signal.SIGINT, key_ctrl_c)

class Test():
    def __init__(self, clear=False):
        self.clear = clear
        self.count = 0
        pass

    async def test(self, class_list, tid, round_name):
        global ctrl_c
        for class_ in class_list:
            start = time.time()
            case = re.search(r'Test[a-zA-Z]*', str(class_)).group()
            LOG(msg=f"    {time.strftime('%H:%M:%S')}==>task {tid}: run  - '{case}'")
            try:
                # run the test
                await class_(tid, round_name).test()
            except Exception as e:
                LOG('error', msg=str(e))
            finally:
                if self.clear:
                    await ResourceDB.clear()
            end = time.time()
            tm = end - start
            LOG(msg=f"    {time.strftime('%H:%M:%S')}==>task {tid}: done - '{case}' - time: {int(tm)}s/{int(tm/60)}m")
            if ctrl_c:
                return 'Breaked by user'

    async def run(self, case_class, taskid, use_round_name):
        # case_file::class1,class2  == only run case 1,2
        # case_file::-class3,class4  == exclude case 3,4
        cases = case_class.partition('::')
        cls = __import__(cases[0])
        name_list = []
        case_list = []

        include, _, exclude = cases[2].partition('-')
        only = include.split(',') if include else []
        exclude = exclude.split(',') if exclude else []

        for name, class_ in inspect.getmembers(cls, inspect.isclass):
            # need class start with 'Test' and skip base class
            if not name.startswith('Test') or name == 'TestBase':
                continue
            name_list.append(name)
            # form class for only cases and exclude cases
            if not only or name in only:
                case_list.append(class_)
            elif exclude and name in exclude:
                continue
        # check if cases existed in case file
        diff = set(only + exclude) - set(name_list)
        if diff:
            LOG('error', msg=f'Class {diff} not found in {cases[0]}')
            return

        self.count += 1
        LOG(msg=f'Round {self.count} Ready to run cases: {case_list}')
        if use_round_name:
            round_name = self.count
        else:
            round_name = 0
        # run the case in each thread
        global tasks
        tasks = set()
        for i in range(taskid):
            tid = i + 1
            _task = asyncio.create_task(self.test(case_list, tid, round_name), name=tid)
            _task.add_done_callback(tasks.discard)
            tasks.add(_task)
        await asyncio.gather(*tasks)

async def run(args):
    auth = pasrse_config_file()
    LOG(msg=f"Run testcases in host: {auth['host']}")
    if args.dump:
        ResourceDB.load()
        return

    # clean resources recorded in DB, and clear data in DB
    ResourceDB.load()
    await ResourceDB.clearall()
    ResourceDB.flush()

    if not args.cases:
        return

    # Ready to run the cases
    test = Test(args.clear)
    tm = time.time()
    global ctrl_c
    # 0 times mean forever
    it = repeat(0, args.times) if args.times != 0 else repeat(0)
    #it = range(0, args.times) if args.times != 0 else count(1)
    for _ in it:
        await test.run(args.cases, args.parallel, args.rn)
        if ctrl_c:
            break
    tm = time.time() - tm
    LOG(msg=f'[ Total time: {int(tm)}s/{int(tm/60)}m ]')
    ResourceDB.flush()

def main():
    helps = "casefile OR casefile::class,...; casefile::-class,... to exclude cases\n" \
            "For example:\n" \
            "    ./test.py -c cases::TestRouter"
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-p', '--parallel', default=1, type=int, help='Parallel number, default is 1')
    parser.add_argument('-t', '--times', default=1, type=int, help='Times the test will be run.\n0 means forever, default is 1')
    parser.add_argument('-c', '--cases', help=helps)
    parser.add_argument('-C', '--clear', action='store_true', help='Clear all resources created during test')
    parser.add_argument('-d', '--dump', action='store_true', help='show all resources stored in DB (created during test)')
    parser.add_argument('-n', '--rn', action='store_true', help='Add prefix in resource name for each round')

    parser.set_defaults(func=run)
    args = parser.parse_args(None if sys.argv[1:] else ['-h'])
    asyncio.run(args.func(args))

if __name__ == '__main__':
    main()
