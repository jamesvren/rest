#!/usr/bin/python3
# -*- coding: utf-8 -*-

import gevent
from gevent import monkey
monkey.patch_all()

import argparse
import inspect
import time
import sys
import signal
from resource import ResourceDB

threads = []
ctrl_c = False
key_times = 0
def key_ctrl_c(sig, frame):
    print(f'Please wait for last case finished ...(three times to break)')
    global key_times, ctrl_c
    ctrl_c = True
    key_times += 1
    if key_times == 3:
        try:
            gevent.killall(threads)
        except:
            pass
        finally:
            print('[**] Break by user. Please clear resource manually.')
            ResourceDB.dump()
            ResourceDB.flush()
signal.signal(signal.SIGINT, key_ctrl_c)

class Test():
    def __init__(self, clear=False):
        self.clear = clear
        pass

    def test(self, class_list, thread):
        for class_ in class_list:
            start = time.time()
            print(time.strftime('%H:%M:%S') + f'==>thread {thread}: run {class_}')
            try:
                # run the test
                class_(thread).test()
            finally:
                if self.clear:
                    ResourceDB.clear()
            end = time.time()
            tm = end - start
            print(time.strftime('%H:%M:%S') + f'==>thread {thread}: done - {class_} - time: {int(tm)}s/{int(tm/60)}m')
            global ctrl_c
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
            if not only or  name in only:
                case_list.append(class_)
            elif exclude and name in exclude:
                continue
        diff = set(only + exclude) - set(name_list)
        if diff:
            print(f'Error: Class {diff} not found in {cases[0]}')
            return

        print(f'Ready to run cases: {case_list}')
        # run the case in each thread
        global threads
        threads = []
        for i in range(thread_num):
            threads.append(gevent.spawn(self.test, case_list, i + 1))

        gevent.joinall(threads)

def run(args):
    ResourceDB.load()
    ResourceDB.clearall()
    ResourceDB.flush()

    if not args.cases:
        return

    test = Test(args.clear if args.times==1 else True)
    tm = time.time()
    global ctrl_c
    if args.times == 0:
        # 0 times mean forever
        while args.times == 0 and not ctrl_c:
            print(f'control c is {ctrl_c}')
            test.run(args.cases, args.parallel)
    else:
        for i in range(args.times):
            if ctrl_c:
                break
            test.run(args.cases, args.parallel)
    tm = time.time() - tm
    print(f'[ Total time: {int(tm)}s/{int(tm/60)}m ]')
    ResourceDB.flush()

def main():
    helps = "casefile OR casefile::class,...; casefile::-class,... to exclude cases\n" \
            "For example:\n" \
            "    ./test.py -c testcase::TestRouter"
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-p', '--parallel', default=1, type=int, help='Parallel number')
    parser.add_argument('-t', '--times', default=1, type=int, help='Times the test will be run.\n0 means forever, default is 1')
    parser.add_argument('-c', '--cases', help=helps)
    parser.add_argument('-C', '--clear', action='store_true', help='Clear all resources created during test')

    #if len(sys.argv) < 2:
    #    parser.print_usage()
    #    sys.exit(1)

    parser.set_defaults(func=run)
    args = parser.parse_args(None if sys.argv[1:] else ['-h'])
    args.func(args)

if __name__ == '__main__':
    main()
