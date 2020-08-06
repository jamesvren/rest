#!/usr/bin/python
# -*- coding: utf-8 -*-
import requests
import json
import sys
import os
import re
import getopt

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
        if self.token:
            return
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
                           'name': self.project \
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
        if res.status_code == 401:
            return None
        if (self.version == 'v2'):
            token = json.loads(res.text)
            self.token = token['access']['token']['id']
        else:
            self.token = res.headers['x-subject-token']
        self.headers['X-Auth-Token'] = self.token
        return self.token

    def get_resource(self, url):
        self.get_token()
        self.headers['X-Auth-Token'] = self.token
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
        self.headers['X-Auth-Token'] = self.token
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
        self.headers['X-Auth-Token'] = self.token
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
        self.headers['X-Auth-Token'] = self.token
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
    print """
Usage:
    python rest.py [-h <ip> [-p <password>]] -f sample.json

Define json file with context like following:

{
"user": "auth_user",
# Support comment per line
# Remove "password" field if no authentication needed.
"password": "password",
"auth_host": "auth host ip",
"project": "project",
"host": "api host ip",
"method": "get, set",
"api": "/url",
"body":
{
    "post body": {
    }
}

}

Create auth.json in same dir with rest.py if want to use auth info for all requests:
{
"user": "admin",
"password": "password",
"project": "admin",
"auth_host": "x.x.x.x",
"auth_port": "x"
}
"""

def get_token(ip, user='admin', password='admin'):
    rest = RestAPI(url=ip, user=user, password=password, auth_host=ip)
    print rest.get_token()

def get_token_remote(host, password):
    import paramiko
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=host, port=22, username='root', password=password)
    cmd = "source ArcherAdmin-openrc; openstack token issue | sed -n '5p' | awk -F '|' '{print $3}' | tr -d ' ' | tr -d '\n'"
    stdin, stdout, stderr = ssh.exec_command(cmd)
    return stdout.read().decode()

def main(argv):
    config_file = None
    host = None
    password = None
    token = None
    try:
        opts, args = getopt.getopt(argv, "h:f:p:")
    except getopt.GetoptError:
        usage_prompt()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            host = arg
        elif opt == '-p':
            password = arg
        elif opt == '-f':
            config_file = arg
    if host:
        if not password:
            if sys.version_info.major == 2:
                password = raw_input('SSH - Please input password for root:')
            else:
                password = input('SSH - Please input password for root:')
        token = get_token_remote(host, password)
        print("Auth-Token: ", token)

    if not config_file:
        usage_prompt()
        sys.exit(2)

    text = read_comment_json(config_file)
    config = json.loads(text)

    if config is not None:
        host = config['host'].encode("utf-8")
        api = config['api'].encode("utf-8")
        body = config['body']
        method = config['method'].encode("utf-8")

    auth_config = None
    path = os.path.dirname(os.path.abspath(__file__))
    auth_file = path + '/auth.json'
    if os.path.exists(auth_file):
        auth_text = read_comment_json(auth_file)
        auth_config = json.loads(auth_text)
    if not auth_config:
        auth_config = config

    if auth_config is not None:
        if auth_config.has_key('user'):
            user = auth_config['user'].encode("utf-8")
        else:
            user = 'admin'
        if auth_config.has_key('password'):
            password = auth_config['password'].encode("utf-8")
        else:
            password = None
        if auth_config.has_key('project'):
            project = auth_config['project'].encode("utf-8")
        else:
            project = 'admin'
        if auth_config.has_key('version'):
            version = auth_config['version']
        else:
            version = 'v2'
        if auth_config.has_key('auth_port'):
            auth_port = auth_config['auth_port']
        else:
            auth_port = '35357'
        if auth_config.has_key('auth_host'):
            auth_host = auth_config['auth_host'].encode("utf-8")
        else:
            auth_host = host

        rest = RestAPI(host, user=user, password=password, project=project, version=version, auth_host=auth_host, auth_port=auth_port)
        if token:
            rest.token=token

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
        usage_prompt()
    elif sys.argv[1] == 'token':
        get_token(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        main(sys.argv[1:])
