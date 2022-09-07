#!/usr/bin/python3
# -*- coding:utf-8 -*-
from cases import *
import re

class TestClearAll(TestBase):
    def test(self):
        self.clear_net()

    def clear_net(self):
        nets = VirtualNetwork().list()
        for n in nets:
            net = VirtualNetwork(id=n['id'])
            if net.delete() is None:
                if net.action.err.get('exception') == 'NetworkInUse':
                    msg = net.action.err.get('msg', '')
                    # find ref list
                    mg = re.match('.*(\[.*\])', msg)
                    if mg is None:
                        print(f'!!! Got unknow error: {msg}')
                        continue
                    refs = mg.groups()[0].split(',')
                    for ref in refs:
                        # find ref type and id
                        mg = re.match('.*http://.*/(.*)/(.*)\'', ref)

                        if mg.groups()[0] == 'virtual-machine-interface':
                            Port(id=mg.groups()[1]).delete()
                    # ref already be deleted, delete network again
                    net.delete()
