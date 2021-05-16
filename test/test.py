#!/usr/bin/python3
# -*- coding: utf-8 -*-

import gevent
from gevent import monkey
monkey.patch_all()

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
signal.signal(signal.SIGINT, key_ctrl_c)

class Test():
    def __init__(self):
        pass

    def test(self, class_list, thread):
        for class_ in class_list:
            start = time.time()
            print(time.strftime('%H:%M:%S') + f'==>thread {thread}: run {class_}')
            try:
                # run the test
                class_(thread).test()
            finally:
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
        for i in range(int(thread_num)):
            threads.append(gevent.spawn(self.test, case_list, i + 1))
        #try:
        gevent.joinall(threads)
        #except KeyboardInterrupt as e:
        #    print(f'Please wait for resource clear ...')
        #    gevent.kill(threads)
        #finally:
        #    ResourceDB.clearall()

def usage():
    print('Usage: ./stablity.py <thread_num> CASES [times]')
    print('  CASES - casefile OR casefile::class,class,...')
    print('  times - 0 means forever, default is 1')

def main():
    if len(sys.argv) < 3:
        usage()
        return
    times = 1
    if len(sys.argv) == 4:
        times = int(sys.argv[3])
    thread_num = sys.argv[1]
    testcase = sys.argv[2]
    test = Test()
    tm = time.time()
    for i in range(times):
        test.run(testcase, thread_num)
    if times != 0:
        tm = time.time() - tm
        print(f'[ Total time: {int(tm)}s/{int(tm/60)}m ]')
    # 0 times mean forever
    global ctrl_c
    while times == 0 and not ctrl_c:
        test.run(testcase, thread_num)

if __name__ == '__main__':
    main()
