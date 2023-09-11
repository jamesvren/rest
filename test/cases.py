#!/usr/bin/python3
# -*- coding:utf-8 -*-

from testbase import TestBase
from resource import *

class TestCases(TestBase):
    async def test(self):
        #net, _ = await TestNetwork(self.T, self.rounds).create(external=True)
        net, _ = await TestNetwork(self.T, self.rounds).create()
        await TestSubnet(self.T, self.rounds).create(net.id)
        #router = await TestRouter(self.T, self.rounds).create()

class TestNetwork(TestBase):
    async def test(self):
        # create private network
        net, _ = await self.create()
        await self.create_subnet(net)
        # create public network

    async def create(self, name=None, external=False, segment=None, provider='self'):
        if not name:
            name = self.res_name
        if external:
            name = 'public_' + name
        net = VirtualNetwork(name=name)
        net.provider = provider
        net.external = external
        if segment:
            net.segment = segment
        elif external:
            net.segment = self.vlan
        res = await net.create()
        #res = net.show()
        return net, res

    async def create_subnet(net, prefixs=[]):
        subnets = []
        for prefix in prefixs:
            subnet = Subnet(network=net.id, name=net.name)
            subnet.cidr = prefix
            res = await subnet.create()
            if not res or res.get('cidr') != prefix:
                print(f'Error: Failed to create subnet {prefix} in net {net.name}:{net.id}')
            else:
                subnets.append(subnet)
        return subnets

class TestSubnet(TestBase):
    async def test(self):
        subnet = Subnet(id='2f7b31a9-4a75-43ae-97d2-18974f45b44c')
        await subnet.show()
        #net = VirtualNetwork(name=self.res_name)
        #res = net.create()
        #subnet = self.create(net.id)

    async def create(self, net_id, name=None):
        if not name:
            name = self.res_name
        subnet = Subnet(network=net_id, name=name)
        subnet.cidr = self.res_prefix
        res = await subnet.create()
        #if res.get('cidr') != self.res_prefix:
        #    print(f'Failed to create subnet {self.res_prefix} in {name}:{net_id}')
        #    return
        return subnet, res

class TestPort(TestBase):
    async def test(self):
        port, _ = await self.create()
        #await port.show()
        await port.list()
        await port.delete()

    async def create(self, name=None):
        if not name:
            name = self.res_name
        net, _ = await TestNetwork(self.T, self.rounds).create()
        await TestSubnet(self.T, self.rounds).create(net.id)
        port = Port(name=name)
        port.net = net.id
        res = await port.create()
        if not res.get('fixed_ips'):
            port.raise_e('Failure to get IP address', res=res)
        return port, res

class TestRouter(TestBase):
    async def test(self):
        router, _ = await self.create()
        router, res = await self.update(router)
        #time.sleep(5)
        await router.delete()

    async def create(self, name=None):
        if not name:
            name = self.res_name
        router = Router(name=name)
        res = await router.create()
        return router, res

    async def update(self, router):
        #net, _ = await TestNetwork(self.T, self.rounds).create()
        #subnet, _ = await TestSubnet(self.T, self.rounds).create(net.id)
        #router.subnet = subnet.id
        pub_net, _ = await TestNetwork(self.T, self.rounds).create(external=True)
        subnet, _ = await TestSubnet(self.T, self.rounds).create(pub_net.id)
        router.net = pub_net.id
        res = await router.update()
        #port = Port()
        #port.filters['device_id'] = [router.id]
        #port.filters['network_id'] = [pub_net.id]
        #res = await port.list()
        #tm = time.time()
        #while not res:
        #    res = await port.list()
        #print(f'!!! spend {int(time.time()-tm)}s/{int(time.time()-tm)/60}m to get port')
        router.gateway = None
        res = await router.update()
        await pub_net.delete()
        return router, res

class TestVPN(TestBase):
    async def test(self):
        router, _ = await self.create()
        router, res = await self.update(router)
        await router.delete()

    async def create(self, name=None):
        if not name:
            name = self.res_name
        router = Router(name=name)
        res = await router.create()
        return router, res

    async def update(self, router):
        net, res = await TestNetwork(self.T, self.rounds).create(external=False, prefixs=[self.res_prefix])
        subnet_id = res['subnets'][0]
        router.subnet = subnet_id
        pub_net, _ = await TestNetwork(self.T, self.rounds).create(external=True, segment=88 + int(self.T), prefixs=[self.res_prefix])
        router.net = pub_net.id
        res = await router.update()
        port = Port()
        port.filters['device_id'] = router.id
        port.filters['network_id'] = net.id
        res = await port.list()
        while not res:
            res = await port.list()
        return router, res

class TestSecurityGroup(TestBase):
    async def test(self):
        #sg = SecurityGroup(name='allow-all', id='30d8ddf3-d56a-4967-b9dd-ca2045ba79cb')
        sg = SecurityGroup(name='allow-all')
        await asyncio.sleep(1)

class TestIpGroup(TestBase):
    async def test(self):
        ipg = IpGroup(self.res_name)
        print(await ipg.list())
