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
import gevent
import asyncio
import aiohttp
from testbase import DEBUG
from db import ResourceDB

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
        DEBUG('rest', "curl -X POST %s %s-d '%s'" % (auth_url, header_str, json.dumps(body)))
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
            DEBUG('rest', '\ncurl -X GET %s %s | python -m json.tool\n' % (url, header_str))
        else:
            DEBUG('rest', "\ncurl -X %s %s %s-d '%s' | python -m json.tool\n" % (method.upper(), url, header_str, data))

        tm = time.time()
        try:
            res = oper[method](url, data=data, headers=self.headers)
        except Exception as e:
            return 500, str(e)
        DEBUG('rest', res.status_code, 'length:', len(res.content), 'time:', time.time()-tm)
        if res.text:
            try:
                DEBUG('rest', json.dumps(res.json()))
                return res.status_code, res.json()
            except:
                DEBUG('rest', res.text)
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
    if auth_config:
        auth['auth_host'] = auth_config['auth_host']
        auth['host'] = auth_config['host'] if 'host' in auth_config else  auth['auth_host']
        auth['user'] = auth_config['user'] if 'user' in auth_config else 'admin'
        auth['password'] = auth_config['password'] if 'password' in auth_config else None
        auth['project'] = auth_config['project'] if 'project' in auth_config else 'admin'
        auth['version'] = auth_config['version'] if 'version' in auth_config else 'v2'
        auth['auth_port'] = auth_config['auth_port'] if 'auth_port' in auth_config else '5000'
        auth['port'] = 8082
        return auth

class ResourceAction():
    def __init__(self, res_obj=None):
        self.res = res_obj
        self.err = None

        config = pasrse_config_file()
        if not config:
            raise Exception('Please generate auth.json for auth info')

        self.host = config['host']
        self.port = config['port']
        self.api = RestAPI(config['auth_host'], config['auth_port'], config['version'], config['user'], config['password'], config['project'])
        if res_obj:
            self.url = self.api.encode_url(host=self.host, port=self.port, uri=res_obj.url)

    def post(self):
        self.err = None
        code, result = self.api.req('post', self.url, self.res.body)
        if code != 200:
            print(code, result)
            self.err = result
            return None
        return result

    def name_to_id(self, res_type, name):
        res_obj = Resource(res_type)
        res_obj.filters = { 'name' : name}
        res_obj.oper = 'READALL'
        res_id = []

        code, resources = self.api.req('post', self.api.encode_url(uri=res_obj.url), res_obj.body)
        if code != 200:
            raise Exception('Not able to get resource')
        for res in resources:
            if res.get('name') == name:
                res_id.append((res['id'], res.get('fq_name', name)))

        idx = 0
        if len(res_id) > 1:
            print('@@ Found multiple %s:' % res_obj.type)
            for i in range(len(res_id)):
                print(i, res_id[i])
            idx = input('Please select: ')
            idx = int(idx)
            if idx >= len(res_id):
                raise Exception('Your input not in scope')
        if not res_id:
            raise Exception('Error: %s %s Not Found' % (self.res.type, name))
        return res_id[idx][0]

    def fqname_to_id(self, res_type, fqname):
        json_body = {'type': res_type, 'fq_name': fqname}
        url = self.api.encode_url('/fqname-to-id')
        code, ret = self.api.req('post', url, json_body)
        if code != 200:
            print(ret)
            return None
        return ret

def save(func):
    def wrapper(obj, *args, **kwargs):
        r = func(obj, *args, **kwargs)
        ResourceDB.insert(obj)
        return r
    return wrapper

def remove(func):
    def wrapper(obj, *args, **kwargs):
        r = func(obj, *args, **kwargs)
        ResourceDB.remove(obj)
        return r
    return wrapper

class Resource():
    def __init__(self, res_type, uri=None, id=None, name=None):
        self.type = res_type
        self._id = id
        self._name = name
        self.url = '/neutron/' + self.type
        if uri:
            self.url = uri
        self.resource = { 'tenant_id': 'ad88dd5d24ce4e2189a6ae7491c33e9d' }
        self.filters = {}
        self.fields = []
        if self._id:
            self.resource['id'] = self._id
        if self._name:
            self.resource['name'] = self._name
        self.data = {
            'fields': self.fields,
            'resource': self.resource,
            'id': self.id,
            'filters': self.filters
        }
        self.context = {
            'user_id': '44faef681cd34e1c80b8520dd6aebad4',
            'tenant_id': 'ad88dd5d24ce4e2189a6ae7491c33e9d',
            'is_admin': True,
            'request_id': 'req-' + str(uuid.uuid1()),
            'operation': 'READALL',
            'type': self.type
        }
        self.body = {'data': self.data, 'context': self.context}

        self.action = ResourceAction(self)

    def _check_id(self):
        if not self.id and not self.name:
            raise Exception('Missing resurce name or id')
        if not self.id:
            self.id = self.action.name_to_id(self.type, self.name)

    @save
    def create(self):
        self.context['operation'] = 'CREATE'
        res = self.action.post()
        if res:
            self.id = res['id']
        return res

    @remove
    def delete(self):
        self._check_id()
        self.context['operation'] = 'DELETE'
        return self.action.post()

    def update(self):
        self._check_id()
        self.context['operation'] = 'UPDATE'
        return self.action.post()

    def show(self):
        self._check_id()
        self.context['operation'] = 'READ'
        return self.action.post()

    def list(self):
        self.context['operation'] = 'READALL'
        return self.action.post()

    def raise_e(self, msg, res=None):
        msg = f'[{self.type}:{self.oper}] {msg}'
        print(msg)
        if res:
            space = len(max(res.keys(), key=len))
            for k, v in res.items():
                print('{k:<{len}} | {v}'.format(k=k, len=space, v=v))
        raise Exception(msg)

    @property
    def oper(self):
        return self.context.get('operation')
    @oper.setter
    def oper(self, value):
        self.context['operation'] = value

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

class VirtualNetwork(Resource):
    def __init__(self, id=None, name=None):
        super().__init__('network', id=id, name=name)

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
    def provider(self):
        return self.resource.get('provider:physical_network')
    @provider.setter
    def provider(self, value):
        self.resource['provider:physical_network'] = value
    @property
    def segment(self):
        return self.resource.get('provider:segmentation_id')
    @segment.setter
    def segment(self, value):
        self.resource['provider:segmentation_id'] = value

class Subnet(Resource):
    def __init__(self, network=None, id=None, name=None):
        super().__init__('subnet', id=id, name=name)
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
    def add_alloc_pool(self, start, end):
        pool = self.resource.get('allocation_pools')
        if pool:
            pool.append({'start': start, 'end': end})
        else:
            pool = [{'start': start, 'end': end}]
        self.resource['allocation_pools'] = pool

class Port(Resource):
    def __init__(self, id=None, name=None):
        super().__init__('port', id=id, name=name)

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

    def __init__(self, id=None, name=None):
        super().__init__('router', id=id, name=name)
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
    def __init__(self, id=None, name=None):
        super().__init__('loadbalancer', id=id, name=name)
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
    def __init__(self, id=None, name=None):
        super().__init__('listener', id=id, name=name)
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
    def __init__(self, id=None, name=None):
        super().__init__('pool', id=id, name=name)
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
    def __init__(self, id=None, name=None):
        super().__init__('member', id=id, name=name)
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
    def __init__(self, pool=None, id=None, name=None):
        super().__init__('healthmonitor', id=id, name=name)
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
    def __init__(self, id=None, name=None):
        super().__init__('firewall_group', id=id, name=name)
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
    def __init__(self, id=None, name=None):
        super().__init__('firewall_policy', id=id, name=name)
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
    def __init__(self, id=None, name=None):
        super().__init__('firewall_rule', id=id, name=name)
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
    def __init__(self, id=None, name=None):
        super().__init__('ike_policy', id=id, name=name)
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
    def __init__(self, id=None, name=None):
        super().__init__('ipsec_policy', id=id, name=name)
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
    def __init__(self, id=None, name=None):
        super().__init__('vpn_endpoint_group', id=id, name=name)
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
    def endpoint_type(self, value):
        self.resource['endpoint_type'] = value

class VpnService(Resource):
    def __init__(self, id=None, name=None):
        super().__init__('vpn_service', id=id, name=name)
    @property
    def router(self):
        return self.resource.get('router_id')
    @router.setter
    def router(self, value):
        self.resource['router_id'] = value

class VpnConnection(Resource):
    def __init__(self, id=None, name=None):
        super().__init__('ipsec_site_connection', id=id, name=name)
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
    def __init__(self, id=None, name=None):
        super().__init__('qos', id=id, name=name)
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
    def __init__(self, id=None, name=None):
        super().__init__('ipgroup', id=id, name=name)
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
    def __init__(self, id=None, name=None):
        super().__init__('net_provider', id=id, name=name)
    @property
    def interfaces(self):
        return self.resource.get('interfaces')
    @interfaces.setter
    def interfaces(self, value):
        self.resource['insterfaces'] = value

class FloatingIP(Resource):
    def __init__(self, id=None, name=None):
        super().__init__('floatingip', id=id, name=name)
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
    def __init__(self, id=None, name=None):
        super().__init__('security_group', id=id, name=name)
    @property
    def rules(self):
        return self.resource.get('security_group_rules')
    @rules.setter
    def rules(self, value):
        self.resource['security_group_rules'] = value

class SecurityGroupRule(Resource):
    def __init__(self, id=None, name=None):
        super().__init__('security_group_rule', id=id, name=name)
    @property
    def group(self):
        return self.resource.get('security_group_id')
    @group.setter
    def group(self, value):
        self.resource['security_group_id'] = value

class PhysicalRouter(Resource):
    def __init__(self, id=None, name=None):
        super().__init__('physical_router', id=id, name=name)
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
    def __init__(self, id=None, name=None):
        super().__init__('tag', id=id, name=name)
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
    def __init__(self, id=None, name=None):
        super().__init__('service_group', id=id, name=name)

class AddressGroup(Resource):
    def __init__(self, id=None, name=None):
        super().__init__('address_group', id=id, name=name)

class SegFirewall(Resource):
    def __init__(self, id=None, name=None):
        super().__init__('segment_firewall_group', id=id, name=name)

class SegFirewallPolicy(Resource):
    def __init__(self, id=None, name=None):
        super().__init__('segment_firewall_policy', id=id, name=name)

class SegFirewallRule(Resource):
    def __init__(self, id=None, name=None):
        super().__init__('segment_firewall_rule', id=id, name=name)
