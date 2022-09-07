#!/usr/bin/python3
# -*- coding:utf-8 -*-

from testbase import TestBase
from resource import *

class TestNetwork(TestBase):
    def test(self):
        #nets = VirtualNetwork().list()
        #for net in nets:
        #    print('handle %s ...' % net['name'])
        #    if 'AUTO' not in net['name']:
        #        continue
        #    port = Port()
        #    port.filters['network_id'] = [net['id']]
        #    ports = port.list()
        #    for pt in ports:
        #        Port(id=pt['id']).delete()
        #    VirtualNetwork(id=net['id']).delete()
        ##net, _ = self.create()
        for i in range(2820, 6000):
            net = VirtualNetwork(name=self.res_name+str(i))
            net.create()
            subnet = Subnet(network=net.id, name=net.name)
            subnet.cidr=self.res_prefix
            subnet.create()

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
            if not res or res.get('cidr') != prefix:
                print(f'Error: Failed to create subnet {prefix} in net {net.name}:{net.id}')
        res = net.show()
        return net, res

class TestSubnet(TestBase):
    def test(self):
        subnet = Subnet(id='2f7b31a9-4a75-43ae-97d2-18974f45b44c')
        subnet.show()
        #net = VirtualNetwork(name=self.res_name)
        #res = net.create()
        #subnet = self.create(net.id)

    def create(self, net_id, name=None):
        if not name:
            name = self.res_name
        subnet = Subnet(network=net_id, name=name)
        subnet.cidr = self.res_prefix
        res = subnet.create()
        if res.get('cidr') != self.res_prefix:
            print(f'Failed to create subnet {self.res_prefix} in {name}:{net_id}')
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
        time.sleep(5)
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
        port = Port()
        port.filters['device_id'] = [router.id]
        port.filters['network_id'] = [pub_net.id]
        res = port.list()
        tm = time.time()
        while not res:
            res = port.list()
        print(f'!!! spend {int(time.time()-tm)}s/{int(time.time()-tm)/60}m to get port')
        router.gateway = None
        res = router.update()
        return router, res

class TestVPN(TestBase):
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
        port = Port()
        port.filters['device_id'] = router.id
        port.filters['network_id'] = net.id
        res = port.list()
        while not res:
            res = port.list()
        return router, res

class TestSecurityGroup(TestBase):
    def test(self):
        #sg = SecurityGroup(name='allow-all', id='30d8ddf3-d56a-4967-b9dd-ca2045ba79cb')
        sg = SecurityGroup(name='allow-all')
        sg.show()
        gevent.sleep(1)
