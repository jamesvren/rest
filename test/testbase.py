#!/usr/bin/python3
# -*- coding:utf-8 -*-
from abc import abstractmethod, ABCMeta

my = 'james'
res_name = 'stress_' + my
subnet_prefix = 24
subnet_base = '1.0.0.0'
subnet_pub = '200.0.0.0'
vlan_base = 100

def int2ip(num):
    return '.'.join([str(int(num/(256**i)%256)) for i in range(4)][::-1])

def ip2int(ip):
    return sum(int(v) * 256 ** (3 - i) for i,v in enumerate(ip.split('.')))

def get_cidr(base, thread):
    num = ip2int(base) + 256 * int(thread)
    ip = int2ip(num)
    return f'{ip}/{subnet_prefix}'

class TestBase(metaclass=ABCMeta):
    def __init__(self, thread):
        self.T = str(thread)
        self.res_name = res_name + self.T
        self.vlan = vlan_base + int(self.T)
        self.res_prefix = get_cidr(subnet_base, thread)
        self.res_pub_prefix = get_cidr(subnet_pub, thread)
        self.objs = []

    @abstractmethod
    def test(self):
        pass

# module_on = ['rest', 'db', 'case']
module_on = [
    #'rest',
    'db',
    'case',
]

def DEBUG(module, *msg):
    global module_on
    if module in module_on:
        print(*msg)

