#!/usr/bin/python3
# -*- coding: utf-8 -*-

import gevent
from gevent import monkey
monkey.patch_all()

import argparse
import inspect
import time
import sys
import os
import signal
import re
from resource import ResourceDB, pasrse_config_file

def msg(*args):
    print(*args)

threads = []
ctrl_c = False
key_times = 0
def key_ctrl_c(sig, frame):
    global key_times, ctrl_c
    ctrl_c = True
    key_times += 1
    msg(f'Please wait for last case finished ...(three times to break: {key_times} times)')
    if key_times >= 3:
        try:
            gevent.killall(threads)
        except:
            pass
        finally:
            msg('[**] Break by user. Please clear resource manually.')
            ResourceDB.dump()
            ResourceDB.flush()
signal.signal(signal.SIGINT, key_ctrl_c)

class Test():
    def __init__(self, clear=False):
        self.clear = clear
        self.count = 0
        pass

    def test(self, class_list, thread):
        global ctrl_c
        for class_ in class_list:
            start = time.time()
            case = re.search(r'Test[a-zA-Z]*', str(class_)).group()
            msg(f"    {time.strftime('%H:%M:%S')}==>thread {thread}: run  - '{case}'")
            try:
                # run the test
                class_(thread).test()
            except Exception as e:
                msg(str(e))
            finally:
                if self.clear:
                    ResourceDB.clear()
            end = time.time()
            tm = end - start
            msg(f"    {time.strftime('%H:%M:%S')}==>thread {thread}: done - '{case}' - time: {int(tm)}s/{int(tm/60)}m")
            if ctrl_c:
                return 'Breaked by user'

    def run(self, case_class, thread_num):
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
            msg(f'Error: Class {diff} not found in {cases[0]}')
            return

        self.count += 1
        msg(f'{self.count} Ready to run cases: {case_list}')
        # run the case in each thread
        global threads
        threads = []
        for i in range(thread_num):
            gid = gevent.spawn(self.test, case_list, i + 1)
            ResourceDB.tasks[id(gid)] = i + 1
            threads.append(gid)

        gevent.joinall(threads)

def run(args):
    auth = pasrse_config_file()
    print(f"Run testcases in host: {auth['host']}")
    if args.dump:
        ResourceDB.dump()
        return

    # clean resources recorded in DB, and clear data in DB
    ResourceDB.load()
    ResourceDB.clearall()
    ResourceDB.flush()

    if not args.cases:
        return

    # Ready to run the cases
    test = Test(args.clear if args.times==1 else True)
    tm = time.time()
    global ctrl_c
    if args.times == 0:
        # 0 times mean forever
        while args.times == 0 and not ctrl_c:
            test.run(args.cases, args.parallel)
    else:
        for i in range(args.times):
            if ctrl_c:
                break
            test.run(args.cases, args.parallel)
    tm = time.time() - tm
    msg(f'[ Total time: {int(tm)}s/{int(tm/60)}m ]')
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

    parser.set_defaults(func=run)
    args = parser.parse_args(None if sys.argv[1:] else ['-h'])
    args.func(args)

if __name__ == '__main__':
    main()
