#!/usr/bin/python3
# -*- coding:utf-8 -*-

from testbase import TestBase
from resource import *

class TestNetwork(TestBase):
    def test(self):
        net, _ = self.create()

    def create(self, name=None, external=False, segment=None, provider='self', prefixs=[]):
        if not name:
            name = self.res_name
        if external:
            name = 'public_' + name
        net = VirtualNetwork(name=name)
        net.provider = provider
        net.external = external
        if segment:
            net.segment = segment
        res = net.create()
        for prefix in prefixs:
            subnet = Subnet(network=net.id, name=net.name)
            subnet.cidr = prefix
            res = subnet.create()
            if res.get('cidr') != prefix:
                print('Error: Failed to create subnet {prefix}')
        res = net.show()
        return net, res

class TestSubnet(TestBase):
    def test(self):
        net = VirtualNetwork(name=self.res_name)
        res = net.create()
        subnet = self.create(net.id)

    def create(self, net_id, name=None):
        if not name:
            name = self.res_name
        subnet = Subnet(network=net_id, name=name)
        subnet.cidr = self.res_prefix
        res = subnet.create()
        if res.get('cidr') != self.res_prefix:
            print('Failed to create subnet')
            return
        return subnet, res

class TestPort(TestBase):
    def test(self):
        port, _ = self.create()
        port.show()
        #port.list()

    def create(self, name=None):
        if not name:
            name = self.res_name
        net, _ = TestNetwork(self.T).create(external=False, prefixs=[self.res_prefix])
        port = Port(name=name)
        port.net = net.id
        res = port.create()
        if not res.get('fixed_ips'):
            port.raise_e('Failure to get IP address', res=res)
        return port, res

class TestRouter(TestBase):
    def test(self):
        router, _ = self.create()
        router, res = self.update(router)
        router.delete()

    def create(self, name=None):
        if not name:
            name = self.res_name
        router = Router(name=name)
        res = router.create()
        return router, res

    def update(self, router):
        net, res = TestNetwork(self.T).create(external=False, prefixs=[self.res_prefix])
        subnet_id = res['subnets'][0]
        router.subnet = subnet_id
        pub_net, _ = TestNetwork(self.T).create(external=True, segment=88 + int(self.T), prefixs=[self.res_prefix])
        router.net = pub_net.id
        res = router.update()
        return router, res

