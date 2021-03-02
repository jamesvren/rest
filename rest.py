#!/usr/bin/python3
# -*- coding: utf-8 -*-
import uuid
import json
import sys
import os
import re
import requests
import argparse
import time

OPER = {
    'show': 'READ',
    'list': 'READALL',
    'create': 'CREATE',
    'delete': 'DELETE',
    'update': 'UPDATE',
    'insert': 'INSERT_RULE',
    'remove': 'REMOVE_RULE',
    }

features = {
    'net': 'Virtual Network',
    'subnet': 'Subnet',
    'router': 'Logical Router',
    'prouter': 'Physical Router',
    'port': 'Virtual Machine Interface',
    'lb': 'Loadbalancer',
    'vpn': 'IpSec VPN',
    'fw': 'Firewall',
    'qos': 'Qos',
    'sg': 'Security Group',
    'floatingip': 'Floating IP',
    'provider': 'Public Network Provider',
    'nodes': 'SDN Nodes',
    'tag': 'Tag',
    'address-group': 'Address Group',
    'service-group': 'Service Group',
    'seg-fw': 'Segment Firewall',
}

debug = False
def DEBUG(*msg):
    if debug:
        print(*msg)

def debug_out(*msg):
    enable = False
    if enable:
        print(*msg)

disable_out = False
def out(*msg):
    if not disable_out:
        print(*msg)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', help='Read from Json file')
    parser.add_argument('--host', help='Host to get token from')
    parser.add_argument('--password', help='Password to login host')
    parser.add_argument('--debug', action='store_true', help='Output curl command for each request')
    parser.add_argument('-g', '--gen-auth', action='store_true', help='Generate authenticate file')
    parser.add_argument('-i', '--interface', metavar='HOST', nargs='+', help='Get vrouter interface in the host')
    parser.add_argument('--netns', action='store_true', help='Show namespace VM')
    parser.add_argument('--no-output', action='store_true', help='Don not print result')
    def cmd_file(args):
        debug_out('cmd_file: ', args)
        if args.interface:
            for ip in args.interface:
                vr_interface(ip, args.netns)
            return
        if args.gen_auth:
            auth_host = args.host if args.host else '127.0.0.1'
            password = args.password if args.password else 'ArcherAdmin@123'
            path = os.path.dirname(os.path.abspath(__file__))
            auth_file = path + '/auth.json'
            example_file = path + '/example.json'
            if os.path.exists(auth_file):
                print('File already exist')
                return
            with open(auth_file, 'w') as f:
                f.write('#support line comment\n')
                f.write(json.dumps({
                        'user': 'ArcherAdmin',
                        'password': password,
                        'project': 'ArcherAdmin',
                        'auth_host': auth_host,
                        'auth_port': '6000'
                        }, indent=0))
            with open(example_file, 'w') as ef:
                text = []
                text.append('{')
                text.append('#"user": "ArcherAdmin",')
                text.append('#"password": "%s",' % password)
                text.append('#"project": "ArcherAdmin",')
                text.append('#"auth_host": "%s",' % auth_host)
                text.append('"host": "%s",' % auth_host)
                text.append('"port": "8082",')
                text.append('"api": "/",')
                text.append('"method": "get",')
                text.append('"body":')
                text.append('{')
                text.append('}')
                text.append('}')
                ef.write('\n'.join(text))
            return
        if not args.file:
            parser.print_usage()
            return
        token = None
        config = pasrse_config_file(args.file)
        api = RestAPI(config['auth_host'], config['auth_port'], config['version'], config['user'], config['password'], config['project'])
        if 'header' in config:
            api.add_header(config['header'])
        url = api.encode_url(host=config['host'], port=config['port'], uri=config['api'])
        _, result = api.req(config['method'], url, config['body'])
        if args.no_output:
            global disable_out
            disable_out = True
        out(json.dumps(result, indent=4))

    parser.set_defaults(func=cmd_file)
    subparsers = parser.add_subparsers()
    for feature in sorted(features.keys()):
        p = subparsers.add_parser(feature, argument_default=argparse.SUPPRESS, help=features[feature])
        ft = feature.replace('-', '_')
        if 'parser_%s' % (ft) in globals():
            globals()['parser_%s' % (ft)](p)
    args = parser.parse_args()
    if args.debug:
        global debug
        debug = True
    debug_out('cmd: ', args)
    args.func(args)

def vr_interface(vrouter_ip, show_ns=False):
    import xml.etree.ElementTree as ET
    from prettytable import PrettyTable

    print('VRouter: ', vrouter_ip)
    vm_info = PrettyTable()
    vm_info.field_names = ["VRouter", "VM Name", "Intf Name", "Intf IP", "MetaData IP", "VN", "FIP"]

    res = requests.get(url=f'http://{vrouter_ip}:8085/Snh_VrouterInfoReq')
    if res.status_code != 200:
        print('error: host is not reachable')
        return
    root = ET.fromstring(res.text)
    vrouter_name = root.find('display_name').text
    compute_name = vrouter_name

    res = requests.get(url=f'http://{vrouter_ip}:8085/Snh_ItfReq')
    if res.status_code != 200:
        print('error: host is not reachable')
        return
    res.encoding='utf8'
    root = ET.fromstring(res.text)

    for interface in root.iter('ItfSandeshData'):
        intf_name = interface.find('name').text
        vm_name = interface.find('vm_name').text
        if not show_ns and (vm_name is None or vm_name.startswith('NetNS-')):
            continue
        ip_addr = interface.find('ip_addr').text
        mdata_ip_addr = interface.find('mdata_ip_addr').text
        vn = interface.find('vn_name').text
        if vn:
            vn = vn.split(':')[-1]
        fip = None
        fip_e = interface.find('fip_list')
        for fip_list in fip_e.iter('FloatingIpSandeshList'):
            fip = fip_list.find('ip_addr').text

        if vm_name is not None:
            vm_info.add_row([compute_name, vm_name, intf_name, ip_addr, mdata_ip_addr, vn, fip])
    print(vm_info)

def pair_check(sep, value):
    k,o,v= value.partition(sep)
    if not k or not o or not v:
        raise ValueError()
    return value

def kv(value):
    return pair_check('=', value)

def RANGE(value):
    return pair_check(':', value)

def BOOL(value):
    if value.lower() in ['true', 'yes']:
        return True
    if value.lower() in ['false', 'no']:
        return False
    raise ValueError()

class parser_base():
    def __init__(self, parser):
        self.oper = 'list'
        self.res = None
        self.action = None

        self.parser = parser
        self.operparser = parser.add_subparsers()
        self.create_parser = self.operparser.add_parser('create', argument_default=argparse.SUPPRESS, help='Create a resource')
        self.create_parser.add_argument('--oper', default='create', help=argparse.SUPPRESS)
        self.create_parser.add_argument('name', metavar='NAME', help='Name or ID to be created')
        self.create_parser.add_argument('--id', help='Resource ID to be created')
        self.create_parser.add_argument('--attr', type=kv, metavar='KEY=VALUE', nargs='+',
                                        help='Add additional attribution to a resource')
        self.create_parser.add_argument('--shared', action='store_true', help='Shared resource')

        self.delete_parser = self.operparser.add_parser('delete', help='Delete a resource')
        self.delete_parser.add_argument('--oper', default='delete', help=argparse.SUPPRESS)
        self.delete_parser.add_argument('name', metavar='NAME', help='Name or ID to be deleted')

        self.update_parser = self.operparser.add_parser('update', argument_default=argparse.SUPPRESS, help='Update a resource')
        self.update_parser.add_argument('--oper', default='update', help=argparse.SUPPRESS)
        self.update_parser.add_argument('name', metavar='NAME', help='Name or ID to be updated')
        self.update_parser.add_argument('--attr', type=json.loads,
                                        help='Add additional attribution to a resource')
        self.update_parser.add_argument('--shared', type=BOOL, help='Shared resource')
        self.update_parser.add_argument('--enabled', type=BOOL)

        self.show_parser = self.operparser.add_parser('show', argument_default=argparse.SUPPRESS, help='Show a resource')
        self.show_parser.add_argument('--oper', default='show', help=argparse.SUPPRESS)
        self.show_parser.add_argument('name', metavar='NAME', help='Name or ID to be displayed')

        self.list_parser = self.operparser.add_parser('list', argument_default=argparse.SUPPRESS, help='Show all resources of this type')
        self.list_parser.add_argument('--oper', default='list', help=argparse.SUPPRESS)
        self.list_parser.add_argument('--id', nargs='+', help='Filter by device id')
        self.list_parser.add_argument('--name', nargs='+', help='Filter by name')
        self.list_parser.add_argument('--filters', type=json.loads)
        self.list_parser.set_defaults(func=self.cmd_list)

    def cmd_base(self, args):
        if 'shared' in args:
            self.res.shared = args.shared
        if 'enabled' in args:
            self.res.enabled = args.enabled
        if 'oper' in args:
            self.res.oper = OPER[args.oper]
        if 'name' not in args:
            return
        try:
            uuid.UUID(args.name)
            self.res.id = args.name
        except ValueError as e:
            self.res.name = args.name
        if 'id' in args:
            self.res.id = args.id
            self.res.name = args.name
        if 'attr' in args:
            self.res.resource.update(args.attr)
            #for attr in args.attr:
            #    k,_,v = attr.partition('=')
            #    self.res.resource[k] = v

    def cmd_list(self, args):
        debug_out('cmd_list: ', args)
        self.res.oper = OPER[args.oper]
        if 'net' in args:
            net_id = [self.name_to_id(VirtualNetwork(), net) for net in args.net]
            self.res.filters['network_id'] = net_id
        if 'prefix' in args:
            self.res.filters['prefix'] = args.prefix
        if 'name' in args:
            self.res.filters['name'] = args.name
        if 'id' in args:
            self.res.filters['id'] = args.id
        if 'mac' in args:
            self.res.filters['mac_address'] = args.mac
        if 'status' in args:
            self.res.filters['status'] = args.status
        if 'device' in args:
            self.res.filters['device_id'] = args.device
        if 'filters' in args:
            self.res.filters = args.filters
        self.cmd_action()

    def cmd_action(self, res=None):
        action_res = self.res if not res else res
        if self.action:
            self.action.set_res(action_res)
        else:
            self.action = ResourceAction(action_res)
        self.action.post()

    def name_to_id(self, res, name):
        try:
            return str(uuid.UUID(name))
        except ValueError as e:
            pass
        if self.action:
            self.action.set_res(res)
        else:
            self.action = ResourceAction(res)
        return self.action.name_to_id(name)

class parser_net(parser_base):
    def __init__(self, parser):
        super().__init__(parser)
        self.res = VirtualNetwork()
        group = self.create_parser.add_mutually_exclusive_group()
        group.add_argument('--vlan', default=argparse.SUPPRESS, help='VLAN ID for public network')
        group.add_argument('--vxlan', default=argparse.SUPPRESS, help='VXLAN ID for private network')
        self.create_parser.add_argument('--tag', nargs='*', help='Tag')
        parser.set_defaults(func=self.cmd_net)

    def cmd_net(self, args):
        debug_out('cmd_net: ', args)
        self.cmd_base(args)
        if 'vlan' in args:
            self.res.external = True
            self.res.segment = args.vlan
        if 'vxlan' in args:
            self.res.external = False
            self.res.segment = args.vxlan
        if 'tag' in args:
            self.res.resource['tag'] = args.tag
        self.cmd_action()

class parser_subnet(parser_base):
    def __init__(self, parser):
        super().__init__(parser)
        self.res = Subnet()
        self.create_parser.add_argument('-n', '--net', required=True, help='Network that subnet belong to')
        self.create_parser.add_argument('-p', '--prefix', required=True, help='Prefix of a ubnet')
        self.create_parser.add_argument('--no-dhcp', action='store_true', help='Disable DHCP')
        self.create_parser.add_argument('--no-gateway', action='store_true', help='Disable gateway')
        self.create_parser.add_argument('--pools', type=RANGE, metavar='START:END', nargs='+',
                                        help='Allocation pools')

        self.list_parser.add_argument('--net', nargs='+', help='Filter by network')
        self.list_parser.add_argument('--prefix', nargs='+', help='Filter by prefix')
        parser.set_defaults(func=self.cmd_subnet)

    def cmd_subnet(self, args):
        debug_out('cmd_subnet: ', args)
        self.cmd_base(args)
        if 'net' in args:
            self.res.net = self.name_to_id(VirtualNetwork(), args.net)
        if 'prefix' in args:
            self.res.cidr = args.prefix
        if 'no_dhcp' in args:
            self.res.dhcp = not no_dhcp
        if 'no_gateway' in args:
            self.res.gateway = not no_gateway
        if 'pools' in args:
            for pool in args.pools:
                pool = pool.split('-')
                self.res.add_alloc_pool(pool[0], pool[1])
        self.cmd_action()

class parser_router(parser_base):
    def fixed_ip(value):
        args = value.split(':')
        if len(args) > 2:
            raise ValueError()
        return {'ip_address': args[0], 'subnet_id': args[1]}

    def __init__(self, parser):
        super().__init__(parser)
        self.res = Router()
        gw_parser = self.create_parser.add_subparsers()
        gw = gw_parser.add_parser('gateway', argument_default=argparse.SUPPRESS)
        gw.add_argument('-n', '--net', help='Network of gateway')
        gw.add_argument('-i', '--fixed-ip', help='Fixed IP address of gateway')
        gw.set_defaults(func=self.cmd_gateway)

        subparser = self.update_parser.add_subparsers()
        gw = subparser.add_parser('gateway', argument_default=argparse.SUPPRESS)
        gw.add_argument('-r', '--remove', action='store_true', help='Remove gateway')
        gw.add_argument('-n', '--net', help='Network of gateway')
        gw.add_argument('-i', '--fixed-ip', metavar='IP:SUBNET-ID', type=self.fixed_ip, help='Fixed IP address of gateway')
        gw.set_defaults(func=self.cmd_gateway)
        pf = subparser.add_parser('port-forward', argument_default=argparse.SUPPRESS)
        pf.add_argument('-p', '--protocol', required=True, help='Protocol used in port forwarding')
        pf.add_argument('-s', '--service-port', required=True, help = 'Service port exposed to the public')
        pf.add_argument('--vm-ip', required=True, help='IP of VM in private network')
        pf.add_argument('--vm-port', required=True, help='VM port to supply service')
        pf.set_defaults(func=self.cmd_portforward)

        subnet_g = self.update_parser.add_mutually_exclusive_group()
        subnet_g.add_argument('-s', '--subnet', help='Private subnet')
        subnet_g.add_argument('-S', '--no-subnet', help='Remove private subnet')
        self.update_parser.add_argument('-P', '--no-port-forward', help='Remove port-forwarding')

        self.show_parser.add_argument('-p', '--port', action='store_true', help='Display ports of this router')
        self.show_parser.set_defaults(func=self.cmd_show)

        parser.set_defaults(func=self.cmd_router)

    def cmd_router(self, args):
        debug_out('cmd_router: ', args)
        self.cmd_base(args)
        if 'subnet' in args:
            self.res.oper = 'ADDINTERFACE'
            self.res.subnet = self.name_to_id(Subnet(), args.subnet)
            self.cmd_action()
        if 'no_subnet' in args:
            self.res.oper = 'DELINTERFACE'
            self.res.subnet = self.name_to_id(Subnet(), args.no_subnet)
            self.cmd_action()
        if 'no_port_forward' in args:
            self.res.portforward = None
            self.cmd_action()
        self.res.oper = OPER[args.oper]
        self.cmd_action()

    def cmd_show(self, args):
        debug_out('cmd_show: ', args)
        if 'port' in args:
            res = Port()
            res.filters['device_id'] = [self.name_to_id(Router(), args.name)]
            self.cmd_action(res)
        print('**** Router %s Information ****' % args.name)
        self.cmd_router(args)

    def cmd_gateway(self, args):
        debug_out('cmd_gateway: ', args)
        self.cmd_base(args)
        if 'net' in args:
            self.res.net = self.name_to_id(VirtualNetwork(), args.net)
        if 'fixed_ip' in args:
            self.res.fixed_ip = args.fixed_ip
        if 'remove' in args:
            self.res.gateway = None
        self.cmd_router(args)

    def cmd_portforward(self, args):
        debug_out('cmd_portfoward: ', args)
        pf = self.res.PortForwording(args.protocol, args.vm_ip, args.vm_port, args.service_port)
        self.cmd_base(args)
        self.res.portforward = pf
        self.cmd_router(args)

class parser_port(parser_base):
    def __init__(self, parser):
        super().__init__(parser)
        self.res = Port()
        self.create_parser.add_argument('-n', '--net', required=True, help='Network the port should be created')
        self.create_parser.add_argument('-s', '--subnet', help='Subnet the port should be created')
        self.create_parser.add_argument('--ip', help='Fixed ip address should be allocated')
        self.create_parser.add_argument('--tag', nargs='*', help='Tag')

        self.update_parser.add_argument('-q', '--qos', metavar='Qos-ID', nargs='*', help='Only ingress and egress Qos needed, remove Qos if zero input')
        self.update_parser.add_argument('--tag', nargs='*', help='Tag')

        self.list_parser.add_argument('--net', nargs='+', help='Filter by network')
        self.list_parser.add_argument('--mac', nargs='+', help='Filter by mac address')
        self.list_parser.add_argument('--status', nargs='+', help='Filter by status')
        self.list_parser.add_argument('--device', nargs='+', help='Filter by device id')
        self.list_parser.set_defaults(func=self.cmd_list)

        parser.set_defaults(func=self.cmd_port)

    def cmd_port(self, args):
        debug_out('cmd_port: ', args)
        self.cmd_base(args)
        if 'net' in args:
            self.res.net = self.name_to_id(VirtualNetwork(), args.net)
        if 'subnet' in args:
            self.res.subnet = self.name_to_id(Subnet(), args.subnet)
        if 'ip' in args:
            self.res.ip = args.ip
        if 'qos' in args:
            self.res.qos = args.qos
        if 'tag' in args:
            self.res.resource['tags'] = args.tag
        self.cmd_action()

class parser_floatingip(parser_base):
    def __init__(self, parser):
        super().__init__(parser)
        self.res = FloatingIP()
        self.create_parser.add_argument('-n', '--net', required=True, help='Network the floating ip allocated from')
        self.create_parser.add_argument('-s', '--subnet', help='Subnet the floating ip allocated from')
        self.create_parser.add_argument('--ip', help='Floating ip address should be allocated')
        self.create_parser.add_argument('--fixed-ip', help='Fixed ip address associated with floating ip')
        self.create_parser.add_argument('-p', '--port', help='Port associated with floating ip')
        self.update_parser.add_argument('-p', '--port', nargs='?', help='Port associated with floating ip, remove if no value')
        parser.set_defaults(func=self.cmd_floatingip)

    def cmd_floatingip(self, args):
        debug_out('cmd_floatingip: ', args)
        self.cmd_base(args)
        if 'net' in args:
            self.res.net = self.name_to_id(VirtualNetwork(), args.net)
        if 'subnet' in args:
            self.res.subnet = self.name_to_id(Subnet(), args.subnet)
        if 'ip' in args:
            self.res.ip = args.ip
        if 'fixed_ip' in args:
            self.res.fixed_ip = args.fixed_ip
        if 'port' in args:
            if args.port:
                self.res.port = self.name_to_id(Port(), args.port)
            else:
                self.res.port = None
        self.cmd_action()

class parser_lb(parser_base):
    def __init__(self, parser):
        self.action = None
        self.parser = parser
        parser.add_argument('--config', action='store_true', help='Loadbalancer')
        subparser = self.parser.add_subparsers()
        lb = subparser.add_parser('loadbalancer', aliases=['lb'], help='Loadbalancer')
        parser_loadbalancer(lb)
        listener = subparser.add_parser('listener', help='Listener for loadbalancer')
        parser_listener(listener)
        pool = subparser.add_parser('pool', help='Pool for loadbalancer')
        parser_pool(pool)
        member = subparser.add_parser('member', help='Member of pool')
        parser_member(member)
        monitor = subparser.add_parser('monitor', help='Health monitor for each pool')
        parser_lbmonitor(monitor)
        parser.set_defaults(func=self.cmd_lb)

    def cmd_lb(self, args):
        debug_out('cmd_lb: ', args)
        if 'config' in args:
            self.res = LoadBalancer()
            self.res.url = self.res.url.replace('loadbalancer', 'loadbalancer_config')
            self.cmd_action()
        else:
            self.parser.print_usage()

class parser_loadbalancer(parser_base):
    def __init__(self, parser):
        super().__init__(parser)
        self.res = LoadBalancer()
        self.create_parser.add_argument('-s', '--subnet', required=True, help='VIP subnet')
        self.create_parser.add_argument('-i', '--vip', help='IP address of VIP')
        self.create_parser.add_argument('-p', '--provider', default='arsdn',
                                        choices=['arsdn', 'octavia'], help='Provider of LB')
        self.create_parser.add_argument('--listeners', metavar='LISTENERID', nargs='+', help='Listener ID')
        self.create_parser.add_argument('--pools', metavar='POOLID', nargs='+', help='Pool ID')
        self.create_parser.add_argument('-c', '--cluster', help='Cluster IP')
        self.update_parser.add_argument('--pool', help='Pool ID')

        parser.set_defaults(func=self.cmd_loadbalancer)

    def cmd_loadbalancer(self, args):
        debug_out('cmd_loadbalancer: ', args)
        self.cmd_base(args)
        if 'subnet' in args:
            self.res.subnet = self.name_to_id(Subnet(), args.subnet)
        if 'vip' in args:
            self.res.vip = args.vip
        if 'provider' in args:
            self.res.provider = args.provider
        if 'cluster' in args:
            self.res.cluster = args.cluster
        if 'listerners' in args:
            self.res.listeners = [self.name_to_id(LoadBalanceListener(), l) for l in args.listeners]
        if 'pools' in args:
            self.res.pools = [self.name_to_id(LoadBalancePool(), p) for p in args.pools]
        self.cmd_action()

class parser_listener(parser_base):
    def __init__(self, parser):
        super().__init__(parser)
        self.res = LoadBalanceListener()
        self.create_parser.add_argument('--lb', required=True, help='LoadBalancer for listener')
        self.create_parser.add_argument('--port', required=True, help='Protocol port to listen')
        self.create_parser.add_argument('-p', '--protocol', required=True, help='Protocol to listen',
                                        choices=['tcp', 'http', 'https', 'terminated_https'])
        parser.set_defaults(func=self.cmd_listener)

    def cmd_listener(self, args):
        debug_out('cmd_listener: ', args)
        self.cmd_base(args)
        if 'port' in args:
            self.res.port = args.port
        if 'protocol' in args:
            self.res.protocol = args.protocol.upper()
        if 'lb' in args:
            self.res.lb= self.name_to_id(LoadBalancer(), args.lb)
        self.cmd_action()

class parser_pool(parser_base):
    def __init__(self, parser):
        super().__init__(parser)
        self.res = LoadBalancePool()
        self.create_parser.add_argument('--lb', help='LoadBalancer for pool')
        self.create_parser.add_argument('-l', '--listener', help='Listener for pool')
        self.create_parser.add_argument('-a', '--algorithm', default='round_robin', help='Protocol port to listen',
                                        choices=['round_robin', 'least_connections', 'source_ip'])
        self.create_parser.add_argument('-p', '--protocol', required=True, help='Protocol to listen',
                                        choices=['tcp', 'http', 'https', 'terminated_https'])
        self.create_parser.set_defaults(func=self.cmd_pool_create)
        parser.set_defaults(func=self.cmd_pool)

    def cmd_pool_create(self, args):
        debug_out('cmd_pool_create: ', args)
        self.cmd_base(args)
        if 'algorithm' in args:
            self.res.algorithm = args.algorithm.upper()
        if 'protocol' in args:
            self.res.protocol = args.protocol.upper()
        if 'lb' in args:
            self.res.lb = self.name_to_id(LoadBalancer(), args.lb)
        if 'listener' in args:
            self.res.listener = self.name_to_id(LoadBalanceListener(), args.listener)
        if not self.res.lb and not self.res.listener:
            self.create_parser.error('the following arguments are required: --lb or -l/listener')
        self.cmd_action()

    def cmd_pool(self, args):
        debug_out('cmd_pool: ', args)
        self.cmd_base(args)
        self.cmd_action()

class parser_member(parser_base):
    def __init__(self, parser):
        super().__init__(parser)
        self.res = LoadBalanceMember()
        self.create_parser.add_argument('-s', '--subnet', required=True, help='Subnet the member belong to')
        self.create_parser.add_argument('--port', required=True, help='Service port')
        self.create_parser.add_argument('--ip',  required=True, help='IP address of member')
        self.parser.add_argument('-p', '--pool', required=True, help='Pool the member belong to')

        parser.set_defaults(func=self.cmd_member)

    def cmd_member(self, args):
        debug_out('cmd_member: ', args)
        self.cmd_base(args)
        self.res.pool = self.name_to_id(LoadBalancePool(), args.pool)
        if 'port' in args:
            self.res.port = args.port
        if 'ip' in args:
            self.res.ip = args.ip
        if 'subnet' in args:
            self.res.subnet= self.name_to_id(Subnet(), args.subnet)
        self.cmd_action()
    def cmd_list(self, args):
        self.res.pool = self.name_to_id(LoadBalancePool(), args.pool)
        super().cmd_list(args)

class parser_lbmonitor(parser_base):
    def __init__(self, parser):
        super().__init__(parser)
        self.res = LoadBalanceHealthMonitor()
        self.create_parser.add_argument('-d', '--delay', required=True, help='Interval of monitor check')
        self.create_parser.add_argument('-t', '--timeout', required=True, help='Timeout for monitor')
        self.create_parser.add_argument('-m', '--max-retries', required=True, help='Max retries if timeout')
        self.create_parser.add_argument('-p', '--protocol', required=True, help='Protocol of listner',
                                        choices=['tcp', 'http', 'https'])
        self.parser.add_argument('-p', '--pool', required=True, help='Pool the member belong to')
        parser.set_defaults(func=self.cmd_lbmonitor)

    def cmd_lbmonitor(self, args):
        debug_out('cmd_lbmonitor: ', args)
        self.cmd_base(args)
        self.res.pool = args.pool
        if 'protocol' in args:
            self.res.protocol = args.protocol.upper()
        if 'delay' in args:
            self.res.delay = args.delay
        if 'timeout' in args:
            self.res.timeout = args.timeout
        if 'max_retries' in args:
            self.res.max_retries = args.max_retryies
        self.cmd_action()

class parser_vpn(parser_base):
    def __init__(self, parser):
        self.parser = parser
        subparser = self.parser.add_subparsers()
        ike = subparser.add_parser('ike', help='IKE policy')
        parser_ike(ike)
        ipsec = subparser.add_parser('ipsec', help='IpSec policy')
        parser_ipsec(ipsec)
        endpoint = subparser.add_parser('endpoint', help='VPN endpoint group')
        parser_endpoint(endpoint)
        service = subparser.add_parser('service', help='VPN service')
        parser_service(service)
        connection = subparser.add_parser('connection', help='IpSec connection')
        parser_connection(connection)
        parser.set_defaults(func=self.cmd_vpn)

    def cmd_vpn(self, args):
        self.parser.print_usage()

class parser_ike(parser_base):
    def __init__(self, parser):
        super().__init__(parser)
        self.res = IkePolicy()
        self.create_parser.add_argument('-a', '--auth-algorithm', choices=['sha1','sha256','sha384','sha512'])
        self.create_parser.add_argument('-e', '--encryption-algorithm', choices=['3des','aes-128','aes-192','aes-256'])
        self.create_parser.add_argument('-v', '--ike-version', help='IKE version', choices=['v1','v2'])

        self.update_parser.add_argument('-a', '--auth-algorithm', choices=['sha1','sha256','sha384','sha512'])
        self.update_parser.add_argument('-e', '--encryption-algorithm', choices=['3des','aes-128','aes-192','aes-256'])
        self.update_parser.add_argument('-v', '--ike-version', help='IKE version', choices=['v1','v2'])
        parser.set_defaults(func=self.cmd_ike)

    def cmd_ike(self, args):
        debug_out('cmd_ike: ', args)
        self.cmd_base(args)
        if 'auth_algorithm' in args:
            self.res.auth_algorithm = args.auth_algorithm
        if 'encryption_algorithm' in args:
            self.res.encryption_algorithm = args.encryption_algorithm
        if 'ike_version' in args:
            self.res.ike_version = args.ike_version
        self.cmd_action()

class parser_ipsec(parser_base):
    def __init__(self, parser):
        super().__init__(parser)
        self.res = IpsecPolicy()
        self.create_parser.add_argument('-a', '--auth-algorithm', choices=['sha1','sha256','sha384','sha512'])
        self.create_parser.add_argument('-e', '--encryption-algorithm', choices=['3des','aes-128','aes-192','aes-256'])
        self.create_parser.add_argument('-t', '--transform-protocol', choices=['ESP','AH','AH-ESP'])

        self.update_parser.add_argument('-a', '--auth-algorithm', choices=['sha1','sha256','sha384','sha512'])
        self.update_parser.add_argument('-e', '--encryption-algorithm', choices=['3des','aes-128','aes-192','aes-256'])
        self.update_parser.add_argument('-t', '--transform-protocol', choices=['ESP','AH','AH-ESP'])
        parser.set_defaults(func=self.cmd_ipsec)

    def cmd_ipsec(self, args):
        debug_out('cmd_ipsec: ', args)
        self.cmd_base(args)
        if 'auth_algorithm' in args:
            self.res.auth_algorithm = args.auth_algorithm
        if 'encryption_algorithm' in args:
            self.res.encryption_algorithm = args.encryption_algorithm
        if 'transform_protocol' in args:
            self.res.transform_protocol = args.transform_protocol
        self.cmd_action()

class parser_endpoint(parser_base):
    def __init__(self, parser):
        super().__init__(parser)
        self.res = VpnEndpiointGroup()
        self.create_parser.add_argument('-e', '--endpoints', metavar='IP', required=True,
                                        nargs='+', help='IP address list')
        self.create_parser.add_argument('-t', '--endpoint-type', required=True, choices=['local','remote'])
        parser.set_defaults(func=self.cmd_endpoint)

    def cmd_endpoint(self, args):
        debug_out('cmd_point: ', args)
        self.cmd_base(args)
        if 'endpoints' in args:
            self.res.endpoints = args.endpoints
        if 'endpoint_type' in args:
            self.res.endpoint_type = args.endpoint_type
        self.cmd_action()

class parser_service(parser_base):
    def __init__(self, parser):
        super().__init__(parser)
        self.res = VpnService()
        self.create_parser.add_argument('-r', '--router', required=True, help='Router VPN will associated')
        parser.set_defaults(func=self.cmd_service)

    def cmd_service(self, args):
        debug_out('cmd_servcie: ', args)
        self.cmd_base(args)
        if 'router' in args:
            self.res.router = args.router
        self.cmd_action()

class parser_connection(parser_base):
    def __init__(self, parser):
        super().__init__(parser)
        self.res = VpnConnection()
        self.create_parser.add_argument('--ike', required=True, help='IKE policy')
        self.create_parser.add_argument('--ipsec', required=True, help='IpSec policy')
        self.create_parser.add_argument('-s', '--service', required=True, help='VPN service')
        self.create_parser.add_argument('--peer-ip', required=True, help='Peer gateway IP')
        self.create_parser.add_argument('--peer-id', required=True, help='Peer ID, usaully same as peer ip')
        self.create_parser.add_argument('--psk', required=True, help='Pre-shared key')
        self.create_parser.add_argument('-l', '--local-endpoint', required=True, help='Local endpoint')
        self.create_parser.add_argument('-p', '--peer-endpoint', required=True, help='Peer endpoint')
        parser.set_defaults(func=self.cmd_connection)

    def cmd_connection(self, args):
        debug_out('cmd_connection: ', args)
        self.cmd_base(args)
        if 'ike' in args:
            self.res.ike = self.name_to_id(IkePolicy(), args.ike)
        if 'ipsec' in args:
            self.res.ipsec = self.name_to_id(IpsecPolicy(), args.ipsec)
        if 'service' in args:
            self.res.service = self.name_to_id(VpnService(), args.service)
        if 'peer_ip' in args:
            self.res.peer_ip = args.peer_ip
        if 'peer_id' in args:
            self.res.peer_id = args.peer_id
        if 'psk' in args:
            self.res.psk = args.psk
        if 'local_endpoint' in args:
            self.res.local_endpoint = self.name_to_id(VpnEndpiointGroup(), args.local_endpoint)
        if 'peer_endpoint' in args:
            self.res.peer_endpoint = self.name_to_id(VpnEndpiointGroup(), args.peer_endpoint)
        self.cmd_action()

class parser_fw(parser_base):
    def __init__(self, parser):
        self.parser = parser
        subparser = self.parser.add_subparsers()
        firewall = subparser.add_parser('firewall', help='Firewall group')
        parser_firewall(firewall)
        policy = subparser.add_parser('policy', help='Firewall policy')
        parser_policy(policy)
        rule = subparser.add_parser('rule', help='Policy rule')
        parser_fwrule(rule)
        parser.set_defaults(func=self.cmd_fw)

    def cmd_fw(self, args):
        self.parser.print_usage()

class parser_firewall(parser_base):
    def __init__(self, parser):
        super().__init__(parser)
        self.res = Firewall()
        self.create_parser.add_argument('-p', '--policy', nargs='+', help='Policy to be associated')
        self.create_parser.add_argument('--project', nargs='+', help='Project to be associated')
        self.create_parser.add_argument('--network', nargs='+', help='Netwrok to be associated')
        self.create_parser.add_argument('--port', nargs='+', help='Port to be associated')

        self.update_parser.add_argument('-p', '--policy', nargs='+', help='Policy to be associated')
        self.update_parser.add_argument('--project', nargs='+', help='Project to be associated')
        self.update_parser.add_argument('--network', nargs='+', help='Netwrok to be associated')
        self.update_parser.add_argument('--port', nargs='+', help='Port to be associated')

        parser.set_defaults(func=self.cmd_firewall)

    def cmd_firewall(self, args):
        debug_out('cmd_firewall: ', args)
        self.cmd_base(args)
        if 'policy' in args:
            self.res.policys = [self.name_to_id(FwPolicy(), p) for p in args.policy]
        if 'project' in args:
            self.res.projects = args.project
        if 'network' in args:
            self.res.networks = [self.name_to_id(VirtualNetwork(), n) for n in args.network]
        if 'port' in args:
            self.res.ports = [self.name_to_id(Port(), p) for p in args.port]
        self.cmd_action()

class parser_policy(parser_base):
    def __init__(self, parser):
        super().__init__(parser)
        self.res = FwPolicy()
        self.create_parser.add_argument('-r', '--rules', nargs='+', help='Rule to be associated')
        self.create_parser.add_argument('--audited', type=bool)
        self.update_parser.add_argument('-r', '--rules', nargs='+', help='Rule to be associated')
        self.update_parser.add_argument('--audited', type=bool)
        self.insert_parser = self.operparser.add_parser('insert', argument_default=argparse.SUPPRESS, help='insert a rule')
        self.insert_parser.add_argument('--oper', default='insert', help=argparse.SUPPRESS)
        self.insert_parser.add_argument('-r', '--rule')
        self.insert_parser.add_argument('name', metavar='NAME', help='Name or ID to be updated')
        self.insert_parser.add_argument('-b', '--before', metavar='RULE', help='Insert before this rule')
        self.insert_parser.add_argument('-a', '--after', metavar='RULE', help='Insert after this rule')
        self.remove_parser = self.operparser.add_parser('remove', argument_default=argparse.SUPPRESS, help='remove a rule')
        self.remove_parser.add_argument('--oper', default='remove', help=argparse.SUPPRESS)
        self.remove_parser.add_argument('name', metavar='NAME', help='Name or ID to be updated')
        self.remove_parser.add_argument('-r', '--rule', metavar='RULE', help='Remove this rule')
        parser.set_defaults(func=self.cmd_policy)

    def cmd_policy(self, args):
        debug_out('cmd_policy: ', args)
        self.cmd_base(args)
        if 'rules' in args:
            self.res.rules = [self.name_to_id(FwRule(), r) for r in args.rules]
        if 'audited' in args:
            self.res.audited = args.audited
        if 'rule' in args:
            self.res.rule = self.name_to_id(FwRule(), args.rule)
        if 'before' in args:
            self.res.insert_before = self.name_to_id(FwRule(), args.before)
        if 'after' in args:
            self.res.resource['insert_after'] = self.name_to_id(FwRule(), args.after)
        self.cmd_action()

class parser_fwrule(parser_base):
    def __init__(self, parser):
        super().__init__(parser)
        self.res = FwRule()
        self.create_parser.add_argument('--src-ip', help='Source IP to be matched')
        self.create_parser.add_argument('--src-port', help='Source port to be matched')
        self.create_parser.add_argument('--dest-ip', help='Destination IP to be matched')
        self.create_parser.add_argument('--dest-port', help='Destination port to be matched')
        self.create_parser.add_argument('-p', '--protocol', help='Protocol to be matched')
        self.create_parser.add_argument('-v', '--version', choices=['v4','v6'])
        self.create_parser.add_argument('--action', choices=['deny','allow'])
        parser.set_defaults(func=self.cmd_rule)

    def cmd_rule(self, args):
        debug_out('cmd_rule: ', args)
        self.cmd_base(args)
        if 'src_ip' in args:
            self.res.src_ip = args.src_ip
        if 'src_port' in args:
            self.res.src_port = args.src_port
        if 'dest_ip' in args:
            self.res.dest_ip = args.dest_ip
        if 'dest_port' in args:
            self.res.dest_port = args.dest_port
        if 'protocol' in args:
            self.res.protocol = args.protocol
        if 'version' in args:
            self.res.version = args.version
        if 'action' in args:
            self.res.action = args.action
        self.cmd_action()

class parser_qos(parser_base):
    def __init__(self, parser):
        self.parser = parser
        subparser = self.parser.add_subparsers()
        ratelimit = subparser.add_parser('ratelimit', help='Qos rate limit')
        parser_ratelimit(ratelimit)
        ipgroup = subparser.add_parser('ipgroup', help='IP group rate limit')
        parser_ipgroup(ipgroup)
        parser.set_defaults(func=self.cmd_qos)

    def cmd_qos(self, args):
        self.parser.print_usage()

class parser_ratelimit(parser_base):
    def __init__(self, parser):
        super().__init__(parser)
        self.res = Qos()
        self.create_parser.add_argument('-d', '--direction', choices=['ingress','egress'])
        self.create_parser.add_argument('-r', '--rate', help='Max rate with bit')
        self.update_parser.add_argument('-r', '--rate', help='Max rate with bit')
        parser.set_defaults(func=self.cmd_ratelimit)

    def cmd_ratelimit(self, args):
        debug_out('cmd_ratelimit: ', args)
        self.cmd_base(args)
        if 'direction' in args:
            self.res.direction = args.direction
        if 'rate' in args:
            self.res.rate = args.rate
        self.cmd_action()

class parser_ipgroup(parser_base):
    def __init__(self, parser):
        super().__init__(parser)
        self.res = IpGroup()
        self.create_parser.add_argument('-n', '--net', help='Network to be ratelimited')
        self.create_parser.add_argument('--ip', nargs='+', help='IP addresses to be ratelimited')
        self.create_parser.add_argument('-p', '--protocol', choices=['tcp','udp'])
        self.create_parser.add_argument('--port', nargs='+',  help='TCP/UDP port')
        self.create_parser.add_argument('-r', '--ratelimit', help='Qos rate limit to be associated')

        self.update_parser.add_argument('--ip', nargs='+', help='IP addresses to be ratelimited')
        self.update_parser.add_argument('-p', '--protocol', choices=['tcp','udp'])
        self.update_parser.add_argument('--port', nargs='+',  help='TCP/UDP port')
        self.update_parser.add_argument('-r', '--ratelimit', help='Qos rate limit to be associated')
        parser.set_defaults(func=self.cmd_ipgroup)

    def cmd_ipgroup(self, args):
        debug_out('cmd_ipgroup: ', args)
        self.cmd_base(args)
        if 'net' in args:
            self.res.net = self.name_to_id(args.net)
        if 'ip' in args:
            self.res.ip = args.ip
        if 'protocol' in args:
            self.res.protocol = args.protocol
        if 'port' in args:
            self.res.port = [self.name_to_id(Port(), p) for p in args.port]
        if 'ratelimit' in args:
            self.res.ratelimit = args.ratelimit
        self.cmd_action()

class parser_sg(parser_base):
    def __init__(self, parser):
        self.parser = parser
        subparser = self.parser.add_subparsers()
        group = subparser.add_parser('group', help='Security group')
        parser_group(group)
        rule = subparser.add_parser('rule', help='Security group rule')
        parser_sgrule(rule)
        parser.set_defaults(func=self.cmd_sg)

    def cmd_sg(self, args):
        self.parser.print_usage()

class parser_group(parser_base):
    def __init__(self, parser):
        super().__init__(parser)
        self.res = SecurityGroup()
        self.create_parser.add_argument('-d', '--direction', choices=['ingress', 'egress'])
        self.create_parser.add_argument('-a', '--action', choices=['accept', 'deny'], nargs='+', help='IP addresses to be ratelimited')
        self.create_parser.add_argument('-p', '--protocol')
        self.create_parser.add_argument('--port', type=RANGE, metavar='MIN:MAX', help='TCP/UDP port')
        self.create_parser.add_argument('--priority', help='Priority of this rule')
        self.create_parser.add_argument('-v', '--ethertype', choices=['IPv4', 'IPv6'], help='Priority of this rule')

        parser.set_defaults(func=self.cmd_group)

    def cmd_group(self, args):
        debug_out('cmd_group: ', args)
        self.cmd_base(args)
        rule = {}
        if 'direction' in args:
            rule['direction'] = args.direction
        if 'action' in args:
            rule['action'] = args.action
        if 'protocol' in args:
            rule['protocol'] = args.protocol
        if 'port' in args:
            rule['port'] = args.port
        if 'priority' in args:
            rule['priority'] = args.priority
        if 'ethertype' in args:
            rule['ethertype'] = args.ethertype
        if rule:
            self.res.rules = [rule]
        self.cmd_action()

class parser_sgrule(parser_base):
    def __init__(self, parser):
        super().__init__(parser)
        self.res = SecurityGroupRule()
        self.create_parser.add_argument('-d', '--direction', choices=['ingress', 'egress'])
        self.create_parser.add_argument('-a', '--action', choices=['accept', 'deny'], nargs='+', help='IP addresses to be ratelimited')
        self.create_parser.add_argument('-p', '--protocol')
        self.create_parser.add_argument('--port', type=RANGE, metavar='MIN:MAX', help='TCP/UDP port')
        self.create_parser.add_argument('--priority', help='Priority of this rule')
        self.create_parser.add_argument('-v', '--ethertype', choices=['IPv4', 'IPv6'])
        self.create_parser.add_argument('--enable', type=BOOL)
        self.create_parser.add_argument('group', help='Security group associated with')

        self.update_parser.add_argument('-d', '--direction', choices=['ingress', 'egress'])
        self.update_parser.add_argument('-a', '--action', choices=['accept', 'deny'], nargs='+', help='IP addresses to be ratelimited')
        self.update_parser.add_argument('-p', '--protocol')
        self.update_parser.add_argument('--port', type=RANGE, metavar='MIN:MAX', help='TCP/UDP port')
        self.update_parser.add_argument('--priority', help='Priority of this rule')
        self.update_parser.add_argument('-v', '--ethertype', choices=['IPv4', 'IPv6'])
        self.update_parser.add_argument('--enable', type=BOOL)
        parser.set_defaults(func=self.cmd_rule)

    def cmd_rule(self, args):
        debug_out('cmd_rule: ', args)
        self.cmd_base(args)
        if 'direction' in args:
            self.res.resource['direction'] = args.direction
        if 'action' in args:
            self.res.resource['action'] = args.action
        if 'protocol' in args:
            self.res.resource['protocol'] = args.protocol
        if 'port' in args:
            self.res.resource['port'] = args.port
        if 'priority' in args:
            self.res.resource['priority'] = args.priority
        if 'ethertype' in args:
            self.res.resource['ethertype'] = args.ethertype
        if 'enable' in args:
            self.res.resource['enabled'] = args.enable
        self.cmd_action()

class parser_provider(parser_base):
    def __init__(self, parser):
        super().__init__(parser)
        self.res = Provider()
        self.create_parser.add_argument('-i', '--interfaces', type=kv, metavar='HOST=NIC', nargs='+', help='Interface for public network')
        self.update_parser.add_argument('-i', '--interfaces', type=kv, metavar='HOST=NIC', nargs='+', help='Interface for public network')
        parser.set_defaults(func=self.cmd_provider)

    def cmd_provider(self, args):
        debug_out(sys._getframe().f_code.co_name, ': ', args)
        self.cmd_base(args)
        if 'interfaces' in args:
            interfaces = []
            for intf in args.interfaces:
                i = intf.split('=')
                interfaces.append({'host': i[0], 'nic': i[1]})
            self.res.interfaces = args.interfaces
        self.cmd_action()

class parser_nodes():
    def __init__(self, parser):
        self.res = ResBase()
        self.action = None

        self.parser = parser
        self.parser.add_argument('--type', required=True,
                                 choices=['vrouter', 'control', 'config', 'configdb', 'analytics', 'analyticsdb'],
                                 help='Staled node type')
        self.operparser = parser.add_subparsers()
        self.list_parser = self.operparser.add_parser('list')
        self.list_parser.set_defaults(func=self.cmd_list)

        self.delete_parser = self.operparser.add_parser('delete')
        self.delete_parser.add_argument('--hostname', required=True, help='Hostame of staled vrouter')
        #self.delete_parser.add_argument('--ip', required=True, help='IP of staled vrouter')
        self.delete_parser.set_defaults(func=self.cmd_delete)

    def cmd_list(self, args):
        debug_out(sys._getframe().f_code.co_name, ': ', args)
        nodes_map = {'vrouter': 'virtual-routers', 'control': 'bgp-routers', 'config': 'config-nodes',
                     'configdb': 'config-database-nodes', 'analytics': 'analytics-nodes', 'analyticsdb': 'database-nodes'}
        self.res.url = '/' + nodes_map[args.type]
        self.action = ResourceAction(self.res)
        self.action.get()

    def cmd_delete(self, args):
        nodes_map = {'vrouter': 'virtual-router', 'control': 'bgp-router', 'config': 'config-node',
                     'configdb': 'config-database-node', 'analytics': 'analytics-node', 'analyticsdb': 'database-node'}
        default_fq = ['default-global-system-config', args.hostname]
        nodes_fqname = {'vrouter': default_fq, 'config': default_fq, 'configdb': default_fq, 'analytics': default_fq, 'analyticsdb': default_fq,
                        'control': ['default-domain', 'default-project', 'ip-fabric', '__default__', args.hostname]}
        debug_out('cmd_vrouter: ', args)
        self.action = ResourceAction(self.res)
        res_id = self.action.fqname_to_id(nodes_map[args.type], nodes_fqname[args.type])
        if not res_id:
            print(f'error: node {args.hostname} not found')
            return
        # delete node
        if args.type == 'vrouter':
            # delete vmi for vrouter
            vmi = default_fq + ['vhost0']
            vmi_id = self.action.fqname_to_id('virtual-machine-interface', vmi)
            if vmi_id:
                self.res.url = f"/virtual-machine-interface/{vmi_id['uuid']}"
                self.action.set_res(self.res)
                self.action.delete()
        self.res.url = f"/{nodes_map[args.type]}/{res_id['uuid']}"
        self.action.set_res(self.res)
        self.action.delete()

class parser_prouter(parser_base):
    def __init__(self, parser):
        super().__init__(parser)
        self.res = PhysicalRouter()
        self.create_parser.add_argument('-m', '--mgmt-ip', help='Management IP of switch')
        self.create_parser.add_argument('-c', '--community', help='Community for snmp read')
        self.create_parser.add_argument('--type', choices=['embedded', 'tor-agent', 'tor-service-node'], help='Physical router type')
        self.create_parser.add_argument('--check', type=BOOL, help='Physical router connection check')
        self.update_parser.add_argument('-c', '--community', help='Community for snmp read')
        self.update_parser.add_argument('--router-type', choices=['embedded', 'tor-agent', 'tor-service-node'], help='Physical router type')
        self.update_parser.add_argument('--check', type=BOOL, help='Physical router connection check')
        parser.set_defaults(func=self.cmd_prouter)

    def cmd_prouter(self, args):
        debug_out(sys._getframe().f_code.co_name, ': ', args)
        self.cmd_base(args)
        if 'mgmt_ip' in args:
            self.res.mgmt_ip = args.mgmt_ip
        if 'community' in args:
            self.res.snmp = {'v2_community': args.community}
        if 'router_type' in args:
            self.res.router_type = args.router_type
        if 'check' in args:
            self.res.check = args.check
        self.cmd_action()

class parser_tag(parser_base):
    def __init__(self, parser):
        super().__init__(parser)
        self.res = Tag()
        self.create_parser.add_argument('--type', help='type name')
        self.create_parser.add_argument('--value', help='tag value string')
        self.update_parser.add_argument('--type',  help='type name')
        self.update_parser.add_argument('--value', help='tag value string')
        parser.set_defaults(func=self.cmd_tag)

    def cmd_tag(self, args):
        debug_out('cmd_tag: ', args)
        self.cmd_base(args)
        if 'type' in args:
            self.res.type_name = args.type
        if 'value' in args:
            self.res.value = args.value
        self.cmd_action()

class parser_address_group(parser_base):
    def __init__(self, parser):
        super().__init__(parser)
        self.res = AddressGroup()
        self.create_parser.add_argument('--prefixes', nargs='*', help='list of prefix uuid')
        self.update_parser.add_argument('--prefixes', nargs='*', help='list of prefix uuid')
        parser.set_defaults(func=self.cmd_address_group)

    def cmd_address_group(self, args):
        debug_out(sys._getframe().f_code.co_name, ': ', args)
        self.cmd_base(args)
        if 'prefixes' in args:
            self.res.resource['prefixes'] = args.prefixes
        self.cmd_action()

class parser_service_group(parser_base):
    def __init__(self, parser):
        super().__init__(parser)
        self.res = ServiceGroup()
        self.create_parser.add_argument('--services', nargs='*', metavar='{"protocol":value,"port":value}',
                                        type=json.loads, help='protocol support: TCP/UDP/ICMP')
        self.update_parser.add_argument('--services', nargs='*', metavar='{"protocol":value,"port":value}',
                                        type=json.loads, help='protocol support: TCP/UDP/ICMP')
        parser.set_defaults(func=self.cmd_service_group)

    def cmd_service_group(self, args):
        debug_out(sys._getframe().f_code.co_name, ': ', args)
        self.cmd_base(args)
        if 'services' in args:
            self.res.resource['services'] = args.services
        self.cmd_action()

class parser_seg_fw(parser_base):
    def __init__(self, parser):
        self.parser = parser
        subparser = self.parser.add_subparsers()
        firewall = subparser.add_parser('firewall', help='Firewall group')
        parser_seg_firewall(firewall)
        policy = subparser.add_parser('policy', help='Firewall policy')
        parser_seg_policy(policy)
        rule = subparser.add_parser('rule', help='Policy rule')
        parser_seg_fwrule(rule)
        parser.set_defaults(func=self.cmd_fw)

    def cmd_fw(self, args):
        self.parser.print_usage()

class parser_seg_firewall(parser_base):
    def __init__(self, parser):
        super().__init__(parser)
        self.res = SegFirewall()
        self.create_parser.add_argument('-t', '--tag', nargs='?', help='Tag to be associated')
        self.create_parser.add_argument('-p', '--policy', nargs='*', help='Policy to be associated')
        self.update_parser.add_argument('-t', '--tag', nargs='?', help='Tag to be associated')
        self.update_parser.add_argument('-p', '--policy', nargs='*', help='Policy to be associated')
        parser.set_defaults(func=self.cmd_firewall)

    def cmd_firewall(self, args):
        debug_out('cmd_firewall: ', args)
        self.cmd_base(args)
        if 'policy' in args:
            self.res.resource['firewall_policys'] = [self.name_to_id(SegFirewallPolicy(), p) for p in args.policy]
        if 'tag' in args:
            self.res.resource['tag'] = args.tag
        self.cmd_action()

class parser_seg_policy(parser_base):
    def __init__(self, parser):
        super().__init__(parser)
        self.res = SegFirewallPolicy()
        self.create_parser.add_argument('-r', '--rules', nargs='*', help='Rule to be associated')
        self.update_parser.add_argument('-r', '--rules', nargs='*', help='Rule to be associated')
        self.insert_parser = self.operparser.add_parser('insert', argument_default=argparse.SUPPRESS, help='insert a rule')
        self.insert_parser.add_argument('--oper', default='insert', help=argparse.SUPPRESS)
        self.insert_parser.add_argument('-r', '--oper-rules', nargs='*')
        self.insert_parser.add_argument('name', metavar='NAME', help='Name or ID to be updated')
        self.insert_parser.add_argument('-b', '--before', metavar='RULE', help='Insert before this rule')
        self.insert_parser.add_argument('-a', '--after', metavar='RULE', help='Insert after this rule')
        self.remove_parser = self.operparser.add_parser('remove', argument_default=argparse.SUPPRESS, help='remove a rule')
        self.remove_parser.add_argument('--oper', default='remove', help=argparse.SUPPRESS)
        self.remove_parser.add_argument('name', metavar='NAME', help='Name or ID to be updated')
        self.remove_parser.add_argument('-r', '--oper-rules', nargs='*', metavar='RULE', help='Remove rules')
        parser.set_defaults(func=self.cmd_policy)

    def cmd_policy(self, args):
        debug_out('cmd_policy: ', args)
        self.cmd_base(args)
        if 'rules' in args:
            self.res.resource['firewall_rules'] = [self.name_to_id(SegFirewallRule(), r) for r in args.rules]
        if 'oper_rules' in args:
            self.res.resource['oper_rules'] = [self.name_to_id(SegFirewallRule(), r) for r in args.oper_rules]
        if 'before' in args:
            self.res.resource['insert_before'] = self.name_to_id(SegFirewallRule(), args.before)
        if 'after' in args:
            self.res.resource['insert_after']= self.name_to_id(SegFirewallRule(), args.after)
        self.cmd_action()

class parser_seg_fwrule(parser_base):
    def __init__(self, parser):
        super().__init__(parser)
        self.res = SegFirewallRule()
        self.create_parser.add_argument('-d', '--direction', choices=['<>', '<', '>'])
        self.create_parser.add_argument('--action', choices=['deny','pass'])
        self.create_parser.add_argument('--match-tags', nargs='*', help='Tags to be matched, available tags are:'
                                                             'application, deployment, tier, site')
        self.create_parser.add_argument('--service-group', help='Service Group name')
        self.create_parser.add_argument('--service', type=json.loads, metavar='{"protocol":value,'
                                                          '"src_port":value,"dst_port":value}',
                                                     help='Protocol supported:'
                                                          'ah, dccp, egp, esp, gre, igmp, ospf, pgm,'
                                                          'rsvp, sctp, udplite, vrrp, icmp6, icmp, tcp, udp, any')
        self.create_parser.add_argument('--endpoint1', type=json.loads, metavar='{"address_group":value,'
                                        '"tags":[values],"network_id":value,"any":bool}')
        self.create_parser.add_argument('--endpoint2', type=json.loads, metavar='{"address_group":value,'
                                        '"tags":[values],"network_id":value,"any":bool}')

        self.update_parser.add_argument('-d', '--direction', choices=['<>', '<', '>'])
        self.update_parser.add_argument('--action', choices=['deny','pass'])
        self.update_parser.add_argument('--match-tags', nargs='*', help='Tags to be matched, available tags are:'
                                                             'application, deployment, tier, site')
        self.update_parser.add_argument('--service-group', help='Service Group name')
        self.update_parser.add_argument('--service', type=json.loads, metavar='{"protocol":value,'
                                                          '"src_port":value,"dst_port":value}',
                                                     help='Protocol supported:'
                                                          'ah, dccp, egp, esp, gre, igmp, ospf, pgm,'
                                                          'rsvp, sctp, udplite, vrrp, icmp6, icmp, tcp, udp, any')
        self.update_parser.add_argument('--endpoint1', type=json.loads, metavar='{"address_group":value,'
                                        '"tags":[values],"network_id":value,"any":bool}')
        self.update_parser.add_argument('--endpoint2', type=json.loads, metavar='{"address_group":value,'
                                        '"tags":[values],"network_id":value,"any":bool}')
        parser.set_defaults(func=self.cmd_rule)

    def cmd_rule(self, args):
        debug_out('cmd_rule: ', args)
        self.cmd_base(args)
        if 'direction' in args:
            self.res.resource['direction'] = args.direction
        if 'action' in args:
            self.res.resource['action'] = args.action
        if 'match_tags' in args:
            self.res.resource['match_tags'] = args.match_tags
        if 'service_group' in args:
            self.res.resource['service_group'] = args.service_group
        if 'service' in args:
            self.res.resource['service'] = args.service
        if 'endpoint1' in args:
            self.res.resource['endpoint_1'] = args.endpoint1
        if 'endpoint2' in args:
            self.res.resource['endpoint_2'] = args.endpoint2
        self.cmd_action()

class ResourceAction():
    def __init__(self, res_obj):
        self.res = res_obj

        config = pasrse_config_file()
        if not config:
            raise Exception('Please generate auth.json for auth info')

        self.host = config['host']
        self.port = config['port']
        self.api = RestAPI(config['auth_host'], config['auth_port'], config['version'], config['user'], config['password'], config['project'])
        self.url = self.api.encode_url(host=self.host, port=self.port, uri=res_obj.url)

    def set_res(self, res_obj):
        self.res = res_obj
        self.url = self.api.encode_url(uri=res_obj.url)

    def name_to_id(self, name):
        self.res.filters = { 'name' : name}
        oper = self.res.oper
        self.res.oper = 'READALL'
        res_id = []

        code, resources = self.api.req('post', self.url, self.res.body)
        if code != 200:
            raise Exception('Not able to get resource')
        for res in resources:
            res_name = res.get('name')
            if res_name == name:
                res_id.append((res['id'], res.get('fq_name', name)))

        idx = 0
        if len(res_id) > 1:
            print('@@ Found multiple %s:' % self.res.type)
            for i in range(len(res_id)):
                print(i, res_id[i])
            idx = input('Please select: ')
            idx = int(idx)
            if idx >= len(res_id):
                raise Exception('Your input not in scope')
        if not res_id:
            raise Exception('Error: %s %s Not Found' % (self.res.type, name))
        self.res.oper = oper
        return res_id[idx][0]

    def fqname_to_id(self, res_type, fqname):
        json_body = {'type': res_type, 'fq_name': fqname}
        self.url = self.api.encode_url('/fqname-to-id')
        code, ret = self.api.req('post', self.url, json_body)
        if code != 200:
            print(ret)
            return None
        return ret

    def post(self):
        if not self.res.id and self.res.oper != 'CREATE' and self.res.oper != 'READALL':
            try:
                self.res.id = self.name_to_id(self.res.name)
            except Exception as e:
                print(str(e))
                return

        code, result = self.api.req('post', self.url, self.res.body)
        if code != 200:
            print(result)
            return
        table = Table(4)
        table.from_json(result)
        print(table)

    def put(self):
        code, result = self.api.req('put', self.url, self.res.body)
        if code != 200:
            print(result)
            return
        table = Table(4)
        table.from_json(result)
        print(table)

    def get(self):
        code, result = self.api.req('get', self.url, self.res.body)
        if code != 200:
            print(result)
            return
        table = Table(4)
        table.from_json(result)
        print(table)

    def delete(self):
        code, result = self.api.req('delete', self.url, self.res.body)
        if code != 200:
            print(result)

# Rest API tools for all kinds of resources
class RestAPI():
    def __init__(self, auth_host, auth_port='35357', version='v2', user='ArcherAdmin',
                 password='ArcherAdmin', project='ArcherAdmin', domain='Default'):
        self.auth_host = auth_host
        self.auth_port = auth_port
        self.version = version
        self.user = user
        self.password = password
        self.project = project
        self.domain = domain
        self.headers = {'Content-Type': 'application/json'}
        self.token = ''
        self.host = None
        self.port = None

    def add_header(self, header):
        self.headers.update(header)

    def get_token(self):
        if self.version == 'v3':
            auth_url = 'http://%s:%s/v3/auth/tokens' % (self.auth_host, self.auth_port)
            body = { 'auth': {
                       'identity': {
                          'methods': ["password"],
                          'password': {
                             'user': {
                              'name': self.user,
                              'password': self.password,
                              'domain': {
                               'name': "Default"
                              }
                             }
                          }
                       },
                       'scope': {
                        'project': {
                           'domain': {
                             'name': "Default"
                           },
                           'name': self.project
                        }
                       }
                     }
                   }
        else:
            auth_url = 'http://%s:%s/v2.0/tokens' % (self.auth_host, self.auth_port)
            body = {
                'auth': {
                    'tenantName':self.project,
                    'passwordCredentials': {
                        'username': self.user,
                        'password': self.password
                    }
                }
            }
        header = {'Content-Type': 'application/json'}
        header_str = '-H "Content-Type:application/json" '
        DEBUG("curl -X POST %s %s-d '%s'" % (auth_url, header_str, json.dumps(body)))
        try:
            res = requests.post(auth_url, data=json.dumps(body), headers=header)
        except Exception as e:
            print(str(e))
            return None
        if res.status_code == 401:
            return None
        if (self.version == 'v2'):
            token = json.loads(res.text)
            self.token = token['access']['token']['id']
        else:
            self.token = res.headers['x-subject-token']
        self.headers['X-Auth-Token'] = self.token
        return self.token

    def req(self, method, url, body=None):
        oper = {
            'get': requests.get,
            'post': requests.post,
            'put': requests.put,
            'delete': requests.delete
        }
        if not self.token:
            self.get_token()
        self.headers['X-Auth-Token'] = self.token
        data = json.dumps(body) if body else None

        header_str = ''
        for (key,value) in self.headers.items():
            header_str += '-H "%s:%s" ' % (key, value)

        if method not in oper.keys():
            print ('Error: not supported rest method (%s)' % method)
            return None

        if method == 'get':
            DEBUG('\ncurl -X GET %s %s | python -m json.tool\n' % (url, header_str))
        else:
            DEBUG("\ncurl -X %s %s %s-d '%s' | python -m json.tool\n" % (method.upper(), url, header_str, data))

        tm = time.time()
        try:
            res = oper[method](url, data=data, headers=self.headers)
        except Exception as e:
            return 500, str(e)
        DEBUG(res.status_code, 'length:', len(res.content), 'time:', time.time()-tm)
        if res.text:
            try:
                DEBUG(json.dumps(res.json()))
                return res.status_code, res.json()
            except:
                DEBUG(res.text)
                return res.status_code, res.text
        else:
            return res.status_code, []

    def encode_url(self, uri, host=None, port=None, api_version=None):
        if not host:
            host = self.host
        else:
            self.host = host
        if not port:
            port = self.port
        else:
            self.port = port
        if (api_version is None):
            return 'http://%s:%s%s' % (host, port, uri)
        else:
            return 'http://%s:%s/%s%s' % (host, port, api_version, uri)

class Table():
    def __init__(self, indent=0):
        self.column = []
        self.raw = []
        self.pretty = []
        self.indent = indent
        self.table = ''
    def add_column(self, column):
        col = [ str(i) for i in column ]
        self.column.append(col)
    def from_json(self, json):
        if isinstance(json, list):
            # multi table
            for item in json:
                self.column = []
                self.add_column(list(item.keys()))
                self.add_column(list(item.values()))
                self._form_table()
        else:
            # single table
            self.add_column(list(json.keys()))
            self.add_column(list(json.values()))
            self._form_table()
    def _form_table(self):
        self.pretty = []
        col = len(self.column)
        raw = len(max(self.column, key=len))
        total = 0
        head = '+'
        for i in range(raw):
            pretty = '|'
            for j in range(col):
                max_item = max(self.column[j], key=len)
                pretty = '{0}{1}{2:<{len}}|'.format(pretty, ' '*self.indent, self.column[j][i],
                                                    len=len(max_item) + self.indent)
                if len(head) != total:
                    head = f"{head}{'-'*(len(max_item)+self.indent*2)}+"
            total = len(pretty)
            self.pretty.append(pretty)
        self.table =  '\n'.join([self.table, head, '\n'.join(self.pretty), head])
    def __str__(self):
        return self.table

# read json have '#' as comment and strip comment
def read_comment_json(file):
    text = ''
    with open(file, 'r') as f:
        all_lines = f.readlines()
    comment = re.compile('\s*#')
    for line in all_lines:
        if not re.match(comment, line):
            text += line
    return text

def auth_from_file():
    auth_config = None
    path = os.path.dirname(os.path.abspath(__file__))
    auth_file = path + '/auth.json'
    if os.path.exists(auth_file):
        auth_text = read_comment_json(auth_file)
        auth_config = json.loads(auth_text)
    return auth_config

def pasrse_config_file(config_file=None):
    auth = {}
    config = None
    auth_config = auth_from_file()
    if config_file:
        text = read_comment_json(config_file)
        config = json.loads(text)
    if not auth_config:
        auth_config = config
    if auth_config:
        auth['auth_host'] = auth_config['auth_host']
        auth['host'] = auth_config['host'] if 'host' in auth_config else  auth['auth_host']
        auth['user'] = auth_config['user'] if 'user' in auth_config else 'admin'
        auth['password'] = auth_config['password'] if 'password' in auth_config else None
        auth['project'] = auth_config['project'] if 'project' in auth_config else 'admin'
        auth['version'] = auth_config['version'] if 'version' in auth_config else 'v2'
        auth['auth_port'] = auth_config['auth_port'] if 'auth_port' in auth_config else '5000'
        port = 8082
        method = 'get'
        api = '/'
        body = {}
        if config:
            if 'auth_host' in config:
                auth['auth_host'] = config['auth_host']
            if 'auth_port' in config:
                auth['auth_port'] = config['auth_port']
            if 'user' in config:
                auth['user'] = config['user']
            if 'password' in config:
                auth['password'] = config['password']
            if 'project' in config:
                auth['project'] = config['project']
            if 'version' in config:
                auth['version'] = config['version']
            if 'host' in config:
                auth['host'] = config['host']
            if 'port' in config:
                port = config['port']
            if 'method' in config:
                method = config['method']
            if 'api' in config:
                api = config['api']
            if 'body' in config:
                body = config['body']
            if 'header' in config:
                auth['header'] = {}
                headers = config['header'].split(';')
                for header in headers:
                    head = header.split(':')
                    if len(head) > 1:
                        auth['header'][head[0]] = head[1]
        auth['port'] = port
        auth['method'] = method
        auth['api'] = api
        auth['body'] = body
        return auth

class ResBase():
    def __init__(self):
        self.url = None
        self.body = {}

class Resource():
    def __init__(self, res_type, res_id=None, name=None):
        self._type = res_type
        self._id = res_id
        self._name = name
        self.url = '/neutron/' + self._type
        self.resource = { 'tenant_id': 'ad88dd5d24ce4e2189a6ae7491c33e9d' }
        if self._id:
            self.resource['id'] = self._id
        if self._name:
            self.resource['name'] = self._name
        self.data = {
            'fields': [],
            'resource': self.resource,
            'id': self.id,
            'filters': {}
        }
        self.context = {
            'user_id': '44faef681cd34e1c80b8520dd6aebad4',
            'tenant_id': 'ad88dd5d24ce4e2189a6ae7491c33e9d',
            'is_admin': True,
            'request_id': 'req-' + str(uuid.uuid1()),
            'operation': 'READALL',
            'type': self._type
        }

    @property
    def type(self):
        return self._type

    @property
    def name(self):
        return self._name
    @name.setter
    def name(self, value):
        self._name = value
        self.resource['name'] = value

    @property
    def id(self):
        return self._id
    @id.setter
    def id(self, value):
        self._id = value
        self.data['id'] = value
        self.resource['id'] = value

    @property
    def filters(self):
        return self.data.get('filters')
    @filters.setter
    def filters(self, value):
        self.data['filters'] = value

    @property
    def fields(self):
        return self.data.get('fields')
    @fields.setter
    def fields(self, value):
        self.data['fields'] = value

    @property
    def shared(self):
        return self.resource.get('shared')
    @shared.setter
    def shared(self, value):
        self.resource['shared'] = value

    @property
    def enabled(self):
        return self.resource.get('admin_state_up')
    @enabled.setter
    def enabled(self, value):
        self.resource['admin_state_up'] = value

    @property
    def oper(self):
        return self.context.get('operation')
    @oper.setter
    def oper(self, oper):
        self.context['operation'] = oper

    @property
    def body(self):
        self._body = {'data': self.data, 'context': self.context}
        return self._body

class VirtualNetwork(Resource):
    def __init__(self, res_id=None, name=None):
        super().__init__('network', res_id=res_id, name=name)

    @property
    def external(self):
        return self.resource.get('router:external')
    @external.setter
    def external(self, value):
        self.resource['router:external'] = value
        if self.resource['router:external']:
            self.resource['provider:network_type'] = 'vlan'
        else:
            self.resource['provider:network_type'] = 'vxlan'

    @property
    def segment(self):
        return self.resource.get('provider:segmentation_id')
    @segment.setter
    def segment(self, value):
        self.resource['provider:segmentation_id'] = value

class Subnet(Resource):
    def __init__(self, network=None, res_id=None, name=None):
        super().__init__('subnet', res_id=res_id, name=name)
        self.resource['network_id'] = network

    @property
    def net(self):
        return self.resource.get('network_id')
    @net.setter
    def net(self, value):
        self.resource['network_id'] = value
    @property
    def cidr(self):
        return self.resource.get('cidr')
    @cidr.setter
    def cidr(self, value):
        self.resource['cidr'] = value
    @property
    def dhcp(self):
        return self.resource.get('enable_dhcp')
    @dhcp.setter
    def dhcp(self, value):
        self.resource['enable_dhcp'] = value
    @property
    def gateway(self):
        return self.resource.get('gateway_ip')
    @gateway.setter
    def gateway(self, value):
        self.resource['gateway_ip'] = value
    def add_alloc_pool(start, end):
        pool = self.resource.get('allocation_pools')
        if pool:
            pool.append({'start': start, 'end': end})
        else:
            pool = [{'start': start, 'end': end}]
        self.resource['allocation_pools'] = pool

class Port(Resource):
    def __init__(self, res_id=None, name=None):
        super().__init__('port', res_id=res_id, name=name)

    @property
    def net(self):
        return self.resource.get('network_id')
    @net.setter
    def net(self, value):
        self.resource['network_id'] = value
    @property
    def subnet(self):
        fixed_ips = self.resource.get('fixed_ips')
        if fixed_ips:
            return fixed_ips.get('subnet_id')
    @subnet.setter
    def subnet(self, value):
        if 'fixed_ips' in self.resource:
            self.resource['fixed_ips'][0]['subnet_id'] = value
        else:
            self.resource['fixed_ips'] = [{'subnet_id': value}]
    @property
    def ip(self):
        fixed_ips = self.resource.get('fixed_ips')
        if fixed_ips:
            return fixed_ips.get('ip_address')
    @ip.setter
    def ip(self, value):
        if 'fixed_ips' in self.resource:
            self.resource['fixed_ips'][0]['ip_address'] = value
        else:
            self.resource['fixed_ips'] = [{'ip_address': value}]
    @property
    def security_groups(self):
        return self.resource.get('security_groups')
    @security_groups.setter
    def security_groups(self, value):
        self.resource['security_groups'] = value
    @property
    def qos(self):
        return self.resource.get('qos')
    @qos.setter
    def qos(self, value):
        self.resource['qos'] = value

class Router(Resource):
    class PortForwording():
        def __init__(self, protocol, vm_ip, vm_port, public_port, status='enable'):
            self.status = status.upper()
            self.vm_ip = vm_ip
            self.vm_port = vm_port
            self.protocol = protocol
            self.public_port = public_port

    def __init__(self, res_id=None, name=None):
        super().__init__('router', res_id=res_id, name=name)
        self._external = None

    @property
    def net(self):
        if self._external:
            return self.resource['external_gateway_info'].get('network_id')
    @net.setter
    def net(self, value):
        if self._external:
            self.resource['external_gateway_info']['network_id'] = value
        else:
            self.resource['external_gateway_info'] = {'network_id': value}
            self._external = self.resource['external_gateway_info']
    @property
    def fixed_ip(self):
        return self.resource.get('external_fixed_ips')
    @fixed_ip.setter
    def fixed_ip(self, value):
        if self._external:
            self.resource['external_gateway_info']['external_fixed_ips'] = value
        self.resource['external_gateway_info'] = {
            'external_fixed_ips': value
        }
    @property
    def gateway(self):
        return self.resource.get('external_gateway_info')
    @gateway.setter
    def gateway(self, value):
        self.resource['external_gateway_info'] = value
    @property
    def subnet(self):
        return self.resource.get('subnet_id')
    @subnet.setter
    def subnet(self, value):
        self.resource['subnet_id'] = value
    @property
    def portforward(self):
        return self.resource.get('portforwardings')
    @portforward.setter
    def portforward(self, value):
        if not value:
            self.resource['portforwardings'] = None
            return
        portforwarding = value.__dict__
        if self.resource.get('portforwardings'):
            self.resource['portforwardings'].append(portforwarding)
        else:
            self.resource['portforwardings'] = [portforwarding]

class LoadBalancer(Resource):
    def __init__(self, res_id=None, name=None):
        super().__init__('loadbalancer', res_id=res_id, name=name)
    @property
    def subnet(self):
        return self.resource.get('vip_subnet_id')
    @subnet.setter
    def subnet(self, value):
        self.resource['vip_subnet_id'] = value
    @property
    def vip(self):
        return self.resource.get('vip_address')
    @vip.setter
    def vip(self):
        self.resource['vip_address'] = value
    @property
    def provider(self):
        return self.resource.get('provider')
    @provider.setter
    def provider(self, value):
        self.resource['provider'] = value
    @property
    def cluster(self):
        return self.resource.get('cluster')
    @cluster.setter
    def cluster(self, value):
        self.resource['cluster'] = value
    @property
    def listeners(self):
        return self.resource.get('listeners')
    @listeners.setter
    def listeners(self, value):
        self.resource['listeners'] = value
    @property
    def pools(self):
        return self.resource.get('pools')
    @pools.setter
    def pools(self, value):
        self.resource['pools'] = value

class LoadBalanceListener(Resource):
    def __init__(self, res_id=None, name=None):
        super().__init__('listener', res_id=res_id, name=name)
    @property
    def lb(self):
        return self.resource.get('loadbalancer_id')
    @lb.setter
    def lb(self, value):
        self.resource['loadbalancer_id'] = value
    @property
    def protocol(self):
        return self.resource.get('protocol')
    @protocol.setter
    def protocol(self, value):
        self.resource['protocol'] = value
    @property
    def port(self):
        return self.resource.get('protocol_port')
    @port.setter
    def port(self, value):
        self.resource['protocol_port'] = value

class LoadBalancePool(Resource):
    def __init__(self, res_id=None, name=None):
        super().__init__('pool', res_id=res_id, name=name)
    @property
    def lb(self):
        return self.resource.get('loadbalancer_id')
    @lb.setter
    def lb(self, value):
        self.resource['loadbalancer_id'] = value
    @property
    def listener(self):
        return self.resource.get('listener_id')
    @listener.setter
    def listener(self, value):
        self.resource['listener_id'] = value
    @property
    def protocol(self):
        return self.resource.get('protocol')
    @protocol.setter
    def protocol(self, value):
        self.resource['protocol'] = value
    @property
    def algorithm(self):
        return self.resource.get('lb_algorithm')
    @algorithm.setter
    def algorithm(self, value):
        self.resource['lb_algorithm'] = value

class LoadBalanceMember(Resource):
    def __init__(self, res_id=None, name=None):
        super().__init__('member', res_id=res_id, name=name)
    @property
    def pool(self):
        return self.resource.get('pool_id')
    @pool.setter
    def pool(self, value):
        self.url = self.url.replace('member', f'pool/{value}/member')
        self.resource['pool_id'] = value
    @property
    def subnet(self):
        return self.resource.get('subnet_id')
    @subnet.setter
    def subnet(self, value):
        self.resource['subnet_id'] = value
    @property
    def port(self):
        return self.resource.get('protocol_port')
    @port.setter
    def port(self, value):
        self.resource['protocol_port'] = value
    @property
    def ip(self):
        return self.resource.get('address')
    @ip.setter
    def ip(self, value):
        self.resource['address'] = value

class LoadBalanceHealthMonitor(Resource):
    def __init__(self, pool=None, res_id=None, name=None):
        super().__init__('healthmonitor', res_id=res_id, name=name)
        self.pool = pool
        self.protocol = 'TCP'
        self.timeout = 10
        self.delay = 60
        self.max_retries = 3

    @property
    def pool(self):
        return self.resource.get('pool_id')
    @pool.setter
    def pool(self, value):
        self.resource['pool_id'] = value
    @property
    def protocol(self):
        return self.resource.get('type')
    @protocol.setter
    def protocol(self, value):
        self.resource['type'] = value
    @property
    def delay(self):
        return self.reource.get('delay')
    @delay.setter
    def delay(self, value):
        self.resource['delay'] = value
    @property
    def timeout(self):
        return self.resource.get('timeout')
    @timeout.setter
    def timeout(self, value):
        self.resource['timeout'] = value
    @property
    def max_retries(self):
        return self.resource.get('max_retries')
    @max_retries.setter
    def max_retries(self, value):
        self.resource['max_retries'] = value

class Firewall(Resource):
    def __init__(self, res_id=None, name=None):
        super().__init__('firewall_group', res_id=res_id, name=name)
    @property
    def policys(self):
        return self.resource.get('firewall_policy_ids')
    @policys.setter
    def policys(self, value):
        self.resource['firewall_policy_ids'] = value
    @property
    def projects(self):
        return self.resource.get('projects')
    @projects.setter
    def projects(self, value):
        self.resource['projects'] = value
    @property
    def ports(self):
        return self.resource.get('ports')
    @ports.setter
    def ports(self, value):
        self.resource['ports'] = value
    @property
    def networks(self):
        return self.resource.get('networks')
    @networks.setter
    def networks(self, value):
        self.resource['networks'] = value

class FwPolicy(Resource):
    def __init__(self, res_id=None, name=None):
        super().__init__('firewall_policy', res_id=res_id, name=name)
    @property
    def rules(self):
        return self.resource.get('firewall_rules')
    @rules.setter
    def rules(self, value):
        self.resource['firewall_rules'] = value
    @property
    def audited(self):
        return self.resource.get('audited')
    @audited.setter
    def audited(self, value):
        self.resource['audited'] = value
    @property
    def rule(self):
        return self.resource.get('firewall_rule_id')
    @rule.setter
    def rule(self, value):
        self.resource['firewall_rule_id'] = value
    @property
    def insert_before(self):
        return self.resource.get('insert_before')
    @insert_before.setter
    def insert_before(self, value):
        self.resource['insert_before'] = value

class FwRule(Resource):
    def __init__(self, res_id=None, name=None):
        super().__init__('firewall_rule', res_id=res_id, name=name)
    @property
    def src_ip(self):
        return self.resource.get('source_ip_address')
    @src_ip.setter
    def src_ip(self, value):
        self.resource['source_ip_address'] = value
    @property
    def dest_ip(self):
        return self.resource.get('destination_ip_address')
    @dest_ip.setter
    def dest_ip(self, value):
        self.resource['destination_ip_address'] = value
    @property
    def src_port(self):
        return self.resource.get('source_port')
    @src_port.setter
    def src_port(self, value):
        self.resource['source_port'] = value
    @property
    def dest_port(self):
        return self.resource.get('destination_port')
    @dest_port.setter
    def dest_port(self, value):
        self.resource['destination_port'] = value
    @property
    def protocol(self):
        return self.resource.get('protocol')
    @protocol.setter
    def protocol(self, value):
        self.resource['protocol'] = value
    @property
    def version(self):
        return self.resource.get('ip_version')
    @version.setter
    def version(self, value):
        self.resource['ip_version'] = value
    @property
    def action(self):
        return self.resource.get('action')
    @action.setter
    def action(self, value):
        self.resource['action'] = value
    @property
    def enabled(self):
        return self.resource.get('enabled')
    @enabled.setter
    def enabled(self, value):
        self.resource['enabled'] = value

class IkePolicy(Resource):
    def __init__(self, res_id=None, name=None):
        super().__init__('ike_policy', res_id=res_id, name=name)
    @property
    def auth_algorithm(self):
        return self.resource.get('auth_algorithm')
    @auth_algorithm.setter
    def auth_algorithm(self, value):
        self.resource['auth_algorithm'] = value
    @property
    def encryption_algorithm(self):
        return self.resource.get('encryption_algorithm')
    @encryption_algorithm.setter
    def encryption_algorithm(self, value):
        self.resource['encryption_algorithm'] = value
    @property
    def ike_version(self):
        return self.resource.get('ike_version')
    @ike_version.setter
    def ike_version(self, value):
        self.resource['ike_version'] = value

class IpsecPolicy(Resource):
    def __init__(self, res_id=None, name=None):
        super().__init__('ipsec_policy', res_id=res_id, name=name)
    @property
    def auth_algorithm(self):
        return self.resource.get('auth_algorithm')
    @auth_algorithm.setter
    def auth_algorithm(self, value):
        self.resource['auth_algorithm'] = value
    @property
    def encryption_algorithm(self):
        return self.resource.get('encryption_algorithm')
    @encryption_algorithm.setter
    def encryption_algorithm(self, value):
        self.resource['encryption_algorithm'] = value
    @property
    def transform_protocol(self):
        return self.resource.get('transform_protocol')
    @transform_protocol.setter
    def transform_protocol(self, value):
        self.resource['transform_protocol'] = value

class VpnEndpiointGroup(Resource):
    def __init__(self, res_id=None, name=None):
        super().__init__('vpn_endpoint_group', res_id=res_id, name=name)
    @property
    def endpoints(self):
        return self.resource.get('endpoints')
    @endpoints.setter
    def endpoints(self, value):
        self.resource['endpoints'] = value
    @property
    def endpoint_type(self):
        return self.resource.get('endpoint_type')
    @endpoint_type.setter
    def endpoints(self, value):
        self.resource['endpoint_type'] = value

class VpnService(Resource):
    def __init__(self, res_id=None, name=None):
        super().__init__('vpn_service', res_id=res_id, name=name)
    @property
    def router(self):
        return self.resource.get('router_id')
    @router.setter
    def router(self, value):
        self.resource['router'] = value

class VpnConnection(Resource):
    def __init__(self, res_id=None, name=None):
        super().__init__('firewall', res_id=res_id, name=name)
    @property
    def ike(self):
        return self.resource.get('ike_policy_id')
    @ike.setter
    def ike(self, value):
        self.resource['ike_policy_id'] = value
    @property
    def ipsec(self):
        return self.resource.get('ipsec_policy_id')
    @ipsec.setter
    def ipsec(self, value):
        self.resource['ipsec_policy_id'] = value
    @property
    def service(self):
        return self.resource.get('vpn_service_id')
    @service.setter
    def service(self, value):
        self.resource['vpn_service_id'] = value
    @property
    def peer_ip(self):
        return self.resource.get('peer_address')
    @peer_ip.setter
    def peer_ip(self, value):
        self.resource['peer_address'] = value
    @property
    def peer_id(self):
        return self.resource.get('peer_id')
    @peer_id.setter
    def peer_id(self, value):
        self.resource['peer_id'] = value
    @property
    def psk(self):
        return self.resource.get('psk')
    @psk.setter
    def psk(self, value):
        self.resource['psk'] = value
    @property
    def local_endpoint(self):
        return self.resource.get('local_ep_group_id')
    @local_endpoint.setter
    def local_endpoint(self, value):
        self.resource['local_ep_group_id'] = value
    @property
    def peer_endpoint(self):
        return self.resource.get('peer_ep_group_id')
    @peer_endpoint.setter
    def peer_endpoint(self, value):
        self.resource['peer_ep_group_id'] = value

class Qos(Resource):
    def __init__(self, res_id=None, name=None):
        super().__init__('qos', res_id=res_id, name=name)
    @property
    def direction(self):
        return self.resource.get('direction')
    @direction.setter
    def direction(self, value):
        self.resource['direction'] = value
    @property
    def rate(self):
        return self.resource.get('max_rate')
    @rate.setter
    def rate(self, value):
        self.resource['max_rate'] = value

class IpGroup(Resource):
    def __init__(self, res_id=None, name=None):
        super().__init__('ipgroup', res_id=res_id, name=name)
    @property
    def net(self):
        return self.resource.get('network_id')
    @net.setter
    def net(self, value):
        self.resource['network_id'] = value
    @property
    def ip(self):
        return self.resource.get('ips')
    @ip.setter
    def ip(self, value):
        self.resource['ips'] = value
    @property
    def protocol(slef):
        return self.resource.get('protocol')
    @protocol.setter
    def protocol(slef, value):
        self.resource['protocol'] = value
    @property
    def port(self):
        return self.resource.get('ports')
    @port.setter
    def port(self, value):
        self.resource['ports'] = value
    @property
    def ratelimit(self):
        return self.resource.get('qos')
    @ratelimit.setter
    def ratelimit(self, value):
        self.resource['qos'] = value

class Provider(Resource):
    def __init__(self, res_id=None, name=None):
        super().__init__('net_provider', res_id=res_id, name=name)
    @property
    def interfaces(self):
        return self.resource.get('interfaces')
    @interfaces.setter
    def interfaces(self, value):
        self.resource['insterfaces'] = value

class FloatingIP(Resource):
    def __init__(self, res_id=None, name=None):
        super().__init__('floatingip', res_id=res_id, name=name)
    @property
    def net(self):
        return self.resource.get('floating_network_id')
    @net.setter
    def net(self, value):
        self.resource['floating_network_id'] = value
    @property
    def subnet(self):
        return self.resource.get('subnet_id')
    @subnet.setter
    def subnet(self, value):
        self.resource['subnet_id'] = value
    @property
    def ip(self):
        return self.resource.get('floating_ip_address')
    @ip.setter
    def ip(self, value):
        self.resource['floating_ip_address'] = value
    @property
    def port(self):
        return self.resource.get('port_id')
    @port.setter
    def port(self, value):
        self.resource['port_id'] = value
    @property
    def fixed_ip(self):
        return self.resource.get('fixed_ip_address')
    @fixed_ip.setter
    def fixed_ip(self, value):
        self.resource['fixed_ip_address'] = value

class SecurityGroup(Resource):
    def __init__(self, res_id=None, name=None):
        super().__init__('security_group', res_id=res_id, name=name)
    @property
    def rules(self):
        return self.resource.get('security_group_rules')
    @rules.setter
    def rules(self, value):
        self.resource['security_group_rules'] = value

class SecurityGroupRule(Resource):
    def __init__(self, res_id=None, name=None):
        super().__init__('security_group_rule', res_id=res_id, name=name)
    @property
    def group(self):
        return self.resource.get('security_group_id')
    @group.setter
    def group(self, value):
        self.resource['security_group_id'] = value

class PhysicalRouter(Resource):
    def __init__(self, res_id=None, name=None):
        super().__init__('physical_router', res_id=res_id, name=name)
    @property
    def mgmt_ip(self):
        return self.resource.get('management_ip')
    @mgmt_ip.setter
    def mgmt_ip(self, value):
        self.resource['management_ip'] = value
    @property
    def snmp(self):
        return self.resource.get('snmp_credentials')
    @snmp.setter
    def snmp(self, value):
        self.resource['snmp_credentials'] = value
    @property
    def router_type(self):
        return self.resource.get('virtual_router_type')
    @router_type.setter
    def router_type(self, value):
        self.resource['virtual_router_type'] = value
    @property
    def connect_check(self):
        return self.resource.get('virtual_router_type')
    @connect_check.setter
    def connect_check(self, value):
        self.resource['virtual_router_type'] = value

class Tag(Resource):
    def __init__(self, res_id=None, name=None):
        super().__init__('tag', res_id=res_id, name=name)
    @property
    def type_name(self):
        return self.resource.get('type_name')
    @type_name.setter
    def type_name(self, value):
        self.resource['type_name'] = value
    @property
    def value(self):
        return self.resource.get('value')
    @value.setter
    def value(self, value):
        self.resource['value'] = value

class ServiceGroup(Resource):
    def __init__(self, res_id=None, name=None):
        super().__init__('service_group', res_id=res_id, name=name)

class AddressGroup(Resource):
    def __init__(self, res_id=None, name=None):
        super().__init__('address_group', res_id=res_id, name=name)

class SegFirewall(Resource):
    def __init__(self, res_id=None, name=None):
        super().__init__('segment_firewall_group', res_id=res_id, name=name)

class SegFirewallPolicy(Resource):
    def __init__(self, res_id=None, name=None):
        super().__init__('segment_firewall_policy', res_id=res_id, name=name)

class SegFirewallRule(Resource):
    def __init__(self, res_id=None, name=None):
        super().__init__('segment_firewall_rule', res_id=res_id, name=name)

if __name__ == '__main__':
    main()
