#!/usr/bin/python3
# -*- coding:utf-8 -*-
from abc import abstractmethod, ABCMeta

my = 'james'
res_name = 'stress_' + my
res_prefix = '%s.5.5.0/24'

class TestBase(metaclass=ABCMeta):
    def __init__(self, thread):
        self.T = str(thread)
        self.res_name = res_name + self.T
        self.res_prefix = res_prefix % thread
        self.objs = []

    @abstractmethod
    def test(self):
        pass

# module_on = ['rest', 'db', 'case']
module_on = [
    #'rest',
    #'db',
    'case',
]

def DEBUG(module, *msg):
    global module_on
    if module in module_on:
        print(*msg)

