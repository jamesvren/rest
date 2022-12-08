#!/usr/bin/python3
# -*- coding:utf-8 -*-
from abc import abstractmethod, ABCMeta
import logging
import os
import time

my = 'james'
res_name = 'stress_' + my
subnet_prefix = 24
subnet_base = '1.0.0.0'
subnet_pub = '200.0.0.0'
vlan_base = 100

module_dep = ['port', 'subnet', 'network', 'router']

# Set up logger

def setup_logger():
    os.makedirs('log', exist_ok=True)
    logger = logging.getLogger(__name__)
    logger.setLevel('DEBUG')
    log_name = f"log/stress_{time.strftime('%y%m%d_%H%M')}.log"
    handler = logging.FileHandler(log_name)
    handler.setLevel('DEBUG')
    formatter = logging.Formatter('%(asctime)s - [%(levelname)s] %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    console = logging.StreamHandler()
    console.setLevel('INFO')
    logger.addHandler(console)
    return logger

log = setup_logger()

def int2ip(num):
    return '.'.join([str(int(num/(256**i)%256)) for i in range(4)][::-1])

def ip2int(ip):
    return sum(int(v) * 256 ** (3 - i) for i,v in enumerate(ip.split('.')))

def get_cidr(base, tid):
    num = ip2int(base) + 256 * int(tid)
    ip = int2ip(num)
    return f'{ip}/{subnet_prefix}'

class TestBase(metaclass=ABCMeta):
    def __init__(self, tid, rounds):
        self.T = str(tid)
        self.rounds = rounds
        #self.res_name += '_' + ''.join(random.sample(string.ascii_letters + string.digits), 8)
        self.res_name = f'{res_name}{self.T}_{self.rounds}'
        self.vlan = vlan_base + int(self.T) + int(self.rounds)*100
        self.res_prefix = get_cidr(subnet_base, tid)
        self.res_pub_prefix = get_cidr(subnet_pub, tid)
        self.objs = []

    @abstractmethod
    async def test(self):
        pass

# module_on = ['rest', 'db', 'case']
module_on = [
    #'rest',
    'db',
    'case',
    'all',
]

def LOG(level='info', module='all', msg=''):
    level_map = {
        'critical': logging.CRITICAL,
        'error': logging.ERROR,
        'warning': logging.WARNING,
        'info': logging.INFO,
        'debug': logging.DEBUG,
    }
    if module in module_on:
        log.log(level_map[level.lower()], msg)
