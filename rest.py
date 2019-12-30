#!/usr/bin/python
# -*- coding: utf-8 -*-
import requests
import json
import sys
import re

class RestAPI():
    def __init__(self, url, password, auth_host, user='admin', project ='admin', version='v2', auth_port='35357'):
        self.url = 'http://' + url
        self.password = password
        self.auth_host= auth_host
        self.auth_port= auth_port
        self.user = user
        self.project = project
        self.version = version
        self.token = ''
        self.headers = {'Content-Type': 'application/json'}

    def get_token(self):
        if self.password is None:
            return
        if (self.version == 'v3'):
            auth_url = 'http://%s:%s/v3/auth/tokens' % (self.auth_host, self.auth_port)
            #body = {'username': self.user, 'project_name': self.project, 'auth_url': 'http://10.131.17.45:45357/v3', 'user_domain_name': 'Default', 'password': '***', 'project_domain_name': 'Default'}
            body = { 'auth': { \
                       'identity': { \
                          'methods': ["password"], \
                          'password': { \
                             'user': { \
                              'name': self.user, \
                              'password': self.password, \
                              'domain': { \
                               'name': "Default" \
                              } \
                             } \
                          } \
                       }, \
                       'scope': { \
                        'project': { \
                           'domain': { \
                             'name': "Default" \
                           }, \
                           'name': "admin" \
                        } \
                       } \
                     } \
                   } 
        else:
            auth_url = 'http://%s:%s/v2.0/tokens' % (self.auth_host, self.auth_port)
            body = { 'auth': {  \
                    'tenantName':self.project, \
                    'passwordCredentials': { \
                        'username': self.user,  \
                        'password': self.password   \
                    }  \
                }  \
            }
        header_str = ''
        for (key,value) in self.headers.items():
            header_str += '-H "%s:%s" ' % (key, value)
        print ("curl -X POST %s %s-d '%s'" % (auth_url, header_str, json.dumps(body)))
        res = requests.post(auth_url, data=json.dumps(body), headers=self.headers)
        if (self.version == 'v2'):
            token = json.loads(res.text)
            self.token = token['access']['token']['id']
        else:
            self.token = res.headers['X-Subject-Token']
        self.headers['X-Auth-Token'] = self.token
        return self.token
    
    def get_resource(self, url):
        self.get_token()
        header_str = ''
        for (key,value) in self.headers.items():
            header_str += '-H "%s:%s" ' % (key, value)
        print ('curl -X GET %s %s | python -m json.tool\n' % (url, header_str))
        res = requests.get(url, headers=self.headers)
        print res.status_code
        rsp = json.dumps(json.loads(res.text), indent=4)
        print rsp
        return rsp

    def set_resource(self, url, body):
        self.get_token()
        header_str = ''
        for (key,value) in self.headers.items():
            header_str += '-H "%s:%s" ' % (key, value)
        print ("curl -X POST %s %s-d '%s' | python -m json.tool\n" % (url, header_str, json.dumps(body)))
        res = requests.post(url, data=json.dumps(body), headers=self.headers)
        print res.status_code
        rsp = json.dumps(json.loads(res.text), indent=4)
        print rsp
        return rsp

    def update_resource(self, url, body):
        self.get_token()
        header_str = ''
        for (key,value) in self.headers.items():
            header_str += '-H "%s:%s" ' % (key, value)
        print ("curl -X PUT %s %s-d '%s' | python -m json.tool\n" % (url, header_str, json.dumps(body)))
        res = requests.put(url, data=json.dumps(body), headers=self.headers)
        print res.status_code
        rsp = json.dumps(json.loads(res.text), indent=4)
        print rsp
        return rsp

    def delete_resource(self, url, body=None):
        self.get_token()
        if body is not None:
            payload = json.dumps(body)
        else:
            payload = None
        header_str = ''
        for (key,value) in self.headers.items():
            header_str += '-H "%s:%s" ' % (key, value)
        print ("curl -X DELETE %s %s-d '%s' | python -m json.tool\n" % (url, header_str, payload))
        res = requests.delete(url, data=payload, headers=self.headers)
        print res.status_code
        rsp = json.dumps(json.loads(res.text), indent=4)
        print rsp
        return rsp

    def encode_url(self, port, api_uri, api_version=None):
        if (api_version is None):
            return '%s:%s%s' % (self.url, port, api_uri)
        else:
            return '%s:%s/%s%s' % (self.url, port, api_version, api_uri)

# end of class RestAPI

# read json have '#' as comment and strip comment
def read_comment_json(file):
    text = ''
    f = open(file, 'r')
    all_lines = f.readlines()
    comment = re.compile('\s*#')
    for line in all_lines:
        if not re.match(comment, line):
            text += line
    return text

def usage_prompt():
    return """
Usage: please specify the config file with context like following:

{
"password": "yourname",
"host": "ip addresss",
"type": "networks, ports, servers, etc.",
"method": "get, set",
"api": "/servers/befe0603-0d7d-4520-9d5b-b8624cb88545/action",
"body":
{
    "your post body": {
    }
}

}

Remove "password" field if no authentication needed.
"""

def get_token(ip, password):
    rest = RestAPI(url=ip, password=password, auth_host=ip)
    print rest.get_token()
    #body = {"qgaIsLive": {}}
                #"cmd":"ip -o link show | grep 02:ff:04:b8:a5:4a | cut -d ':' -f 2 | tr -d ' ' | tr -d '\n'",
    #body = {
    #"qga": {
    #    "async": False,
    #    "timeout": 120,
    #    "cmd": {
    #        "execute": "guest-network-get-interfacesd",
    #        "arguments": {
    #            "id":"xxx"
    #        }
    #    }
    #}
    #}

def main(args):
    config_file = args[1]
    text = read_comment_json(config_file)
    config = json.loads(text)
    #with open(config_file, 'r') as f:
    #    config = json.load(f)

    if config is not None:
        if config.has_key('password'):
            password = config['password'].encode("utf-8")
        else:
            password = None
        if config.has_key('version'):
            version = config['version']
        else:
            version = 'v2'
        if config.has_key('auth_port'):
            auth_port = config['auth_port']
        else:
            auth_port = '35357'
        host = config['host'].encode("utf-8")
        if config.has_key('auth_host'):
            auth_host= config['auth_host'].encode("utf-8")
        else:
            auth_host = host
        api = config['api'].encode("utf-8")
        body = config['body']
        method = config['method'].encode("utf-8")
        
        rest = RestAPI(host, password=password, version=version, auth_host=auth_host, auth_port=auth_port)

        if config.has_key('port'):
            port = config['port']
            url = rest.encode_url(port=port, api_uri=api)
        else:
            res_type = api.split('/', 2)[1]
            if res_type == 'servers':
                url = rest.encode_url(port=8774, api_version='v2.1', api_uri=api)
            elif res_type == 'networks':
                url = rest.encode_url(port=9696, api_version='v2.0', api_uri=api)
            else:
                print "Config Error: No default port found. Please specify port number with 'port'."
                return
        if method == 'get':
            rest.get_resource(url)
        elif method == 'post':
            rest.set_resource(url, body)
        elif method == 'put':
            rest.update_resource(url, body)
        elif method == 'delete':
            rest.delete_resource(url)
        else:
            print 'Error: method "%s" not supported' % method
            return

if __name__ == '__main__':
    if (len(sys.argv) < 2):
        print usage_prompt()
    elif sys.argv[1] == 'token':
        get_token(sys.argv[2], sys.argv[3])
    else:
        main(sys.argv)
