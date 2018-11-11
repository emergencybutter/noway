"""A module for manipulating scaleway VMs.

Example usage:
Once, to generate and save tokens:
    authenticator = noway.Authenticator()
    authenticator.Update()

As many times at you'd like
    authenticator = noway.Authenticator()
    authenticator.Load()
    zc = noway.ZoneConnection(authenticator, noway.AMS_URL)
    zc.Connect()
    server = zc.CreateServer('t0', '9cec5666-d87c-4f2b-8176-19f25e752362')
    server.PowerOn()
    server.WaitForState('running')
    server.WaitForSsh()
    print('powered on')
    server.CleanFromLocalSshHostFile()
    server.ScanAndSaveKeys()
    server.CopyToServer('example.sh', '')
    server.Run(['example.sh'])
"""

import getpass
import http.client
import json
import os
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request

from retrying import retry


class Error(Exception):
    pass


class InvalidState(Exception):
    pass


def _IsInvalidState(x):
    return isinstance(x, InvalidState)


class NoOrganization(Error):
    pass


class InternalError(Error):
    pass


class ShellScriptError(Error):
    pass


def _IsRemoteDisconnected(x):
    return isinstance(x, http.client.RemoteDisconnected)


def _IsHTTPError(x):
    return isinstance(x, urllib.error.HTTPError)


def _IsConnectionRefusedError(x):
    return isinstance(x, ConnectionRefusedError)


AMS_URL = 'https://cp-ams1.scaleway.com'
PAR_URL = 'https://cp-par1.scaleway.com'


def RunLocal(cmd):
    completed_process = subprocess.run(cmd,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
    if completed_process.returncode != 0:
        raise ShellScriptError()
    return (completed_process.stdout, completed_process.stderr)


class HttpJson(object):
    def __init__(self, url):
        self.url = url
        self.default_headers = {'Content-Type': 'application/json'}
        self.connection = None

    def AddHeader(self, header_key, header_value):
        self.default_headers[header_key] = header_value

    def Connect(self):
        parsed_url = urllib.parse.urlparse(self.url)
        if parsed_url.scheme != 'https':
            raise InternalError()
        self.connection = http.client.HTTPSConnection(
            parsed_url.hostname, parsed_url.port)

    def _MakeHeader(self):
        return self.default_headers

    @retry(stop_max_attempt_number=50,
           wait_exponential_multiplier=500,
           wait_exponential_max=10000,
           retry_on_exception=_IsRemoteDisconnected)
    def _JsonRequest(self, method, path, data=None):
        self.connection.request(
            method, path, body=data, headers=self._MakeHeader())
        response = self.connection.getresponse()
        if response.status == 204:
            return None
        return json.loads(response.read().decode('utf-8'))

    def Get(self, path):
        return self._JsonRequest('GET', path)

    def GetRaw(self, path):
        self.connection.request(
            'GET', path, headers=self._MakeHeader())
        response = self.connection.getresponse()
        if response.status == 204:
            return None
        return response.read()

    def Delete(self, path):
        return self._JsonRequest('DELETE', path)

    def Post(self, path, data):
        databytes = json.dumps(data).encode('utf-8')
        return self._JsonRequest('POST', path, data=databytes)

    def Close(self):
        self.connection.close()


class Authenticator(object):
    _URL = 'https://account.scaleway.com'

    def __init__(self):
        self.token_id = None
        self.connection = None

    def _Connection(self):
        if self.connection is None:
            self.connection = HttpJson(Authenticator._URL)
            self.connection.Connect()
        return self.connection

    def Load(self):
        with open('token.json') as f:
            json_data = json.loads(f.read())
            self.token_id = json_data['token_id']
            self.organization_id = json_data['organization_id']

    def Update(self):
        print('Noway Login.\nEmail:')
        email = sys.stdin.readline().rstrip()
        password = getpass.getpass('Password: ')
        data = {'email': email,
                'expires': False,
                'password': password,
                }
        resp = self._Connection().Post('/tokens', data)
        self.token_id = resp['token']['id']
        self.connection.AddHeader('X-Auth-Token', self.token_id)
        self.organization_id = self.DefaultOrganizationId()
        with open('token.json', 'w') as f:
            f.write(json.dumps(
                {'token_id': self.token_id, 'organization_id': self.organization_id}))

    def TokenId(self):
        return self.token_id

    def OrganizationId(self):
        return self.organization_id

    def ListOrganizations(self):
        return self._Connection().Get('/organizations')

    def DefaultOrganization(self):
        # TODO: Better error if no 'organizations' field.
        organizations = self.ListOrganizations()['organizations']
        if len(organizations) < 1:
            raise NoOrganization()
        return organizations[0]

    def DefaultOrganizationId(self):
        return self.DefaultOrganization()['id']

    def ListTokens(self):
        return self.connection.Get('/tokens')

    def DeleteToken(self, token_id):
        return self.connection.Delete('/tokens/' + token_id)


class Volume(object):
    def __init__(self, connection, server_descriptor):
        self.connection = connection
        self.descriptor = server_descriptor

    def id(self):
        return self.descriptor['id']

    def Delete(self):
        return self.connection.DeleteServer(self.id())


class Server(object):
    def __init__(self, connection, server_descriptor):
        self.connection = connection
        self.descriptor = server_descriptor

    def id(self):
        return self.descriptor['id']

    def Name(self):
        return self.descriptor['name']

    def ListActions(self):
        return self.connection.ListServerActions(self.id())

    def PowerOn(self):
        return self.connection.ServerAction(self.id(), 'poweron')

    def PowerOff(self):
        return self.connection.ServerAction(self.id(), 'poweroff')

    def Terminate(self):
        return self.connection.ServerAction(self.id(), 'terminate')

    def StopInPlace(self):
        return self.connection.ServerAction(self.id(), 'stop_in_place')

    def Delete(self):
        return self.connection.DeleteServer(self.id())

    def Refresh(self):
        self.descriptor = self.connection.GetServerDescriptor(self.id())

    def State(self):
        return self.descriptor['state']

    @retry(stop_max_attempt_number=100,
           wait_exponential_multiplier=500,
           wait_exponential_max=5*60000,
           retry_on_exception=_IsInvalidState)
    def WaitForState(self, state):
        self.Refresh()
        current_state = self.State()
        if current_state != state:
            print('State is {}, waiting for {}'.format(
                current_state, state))
            raise InvalidState

    @retry(stop_max_attempt_number=100,
           wait_exponential_multiplier=500,
           wait_exponential_max=10000,
           retry_on_exception=_IsConnectionRefusedError)
    def WaitForSsh(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.Ip(), 22))
        s.recv(1)
        s.close()

    def Ip(self):
        return self.descriptor['public_ip']['address']

    def CleanFromLocalSshHostFile(self):
        home = os.getenv('HOME')
        RunLocal([
            'ssh-keygen',
            '-f',
            os.path.join(home, '.ssh/known_hosts'),
            '-R',
            self.Ip()])

    # Noway is so close to doing SSH decently, but doesn't.
    # Per https://github.com/scaleway/image-tools/issues/36 they have
    # implemented a side channel to fetch ssh key fingerprints through https.
    # However the scripts that runs on their VM to publish the finger print is
    # not run by default, so you have to ssh first and verify the fingerprint
    # when it's too late.
    def ScanAndSaveKeys(self):
        home = os.getenv('HOME')
        out, _ = RunLocal(['ssh-keyscan', self.Ip()])
        with open(os.path.join(home, '.ssh/known_hosts'), 'a') as f:
            f.write(out.decode('utf-8'))

    def Fingerprints(self):
        return self.connection.GetServerHostFingerprints(self.id())

    def CopyToServer(self, src, dest):
        RunLocal(['scp', '-r', src, 'root@' + self.Ip() + ':' + dest])

    def Run(self, cmd):
        return RunLocal(['ssh', '-l', 'root', self.Ip()] + cmd)


class ZoneConnection(object):
    def __init__(self, authenticator, url):
        self.authenticator = authenticator
        self.url = url

    def Connect(self):
        self.connection = HttpJson(self.url)
        self.connection.Connect()
        self.connection.AddHeader('X-Auth-Token', self.authenticator.TokenId())

    def ListServers(self):
        ret = []
        for server_descriptor in self.connection.Get('/servers')['servers']:
            ret.append(Server(self, server_descriptor))
        return ret

    def ListVolumes(self):
        ret = []
        for server_descriptor in self.connection.Get('/volumes')['volumes']:
            ret.append(Volume(self, server_descriptor))
        return ret

    def ListImages(self):
        return self.connection.Get('/images')

    def CreateServer(self, server_name, image_id,
                     commercial_type='VC1S', enable_ipv6=False, boot_type='local'):
        data = {
            'organization': self.authenticator.OrganizationId(),
            'name': server_name,
            'image': image_id,
            'commercial_type': commercial_type,
            'tags': [
                'test',
            ],
            'enable_ipv6': enable_ipv6,
            'boot_type': boot_type
        }
        return Server(self, self.connection.Post(
            '/servers', data=data)['server'])

    def ServerAction(self, server_id, action):
        data = {'action': action}
        path = '/servers/' + server_id + '/action'
        return self.connection.Post(path, data=data)

    def ListServerActions(self, server_id):
        path = '/servers/' + server_id + '/action'
        return self.connection.Get(path)

    def GetServerDescriptor(self, server_id):
        descr = self.connection.Get('/servers/' + server_id)
        return descr['server']

    def GetServer(self, server_id):
        return Server(self, self.GetServerDescriptor(server_id))

    def DeleteServer(self, server_id):
        return self.connection.Delete('/servers/' + server_id)

    def GetServerHostFingerprints(self, server_id):
        return self.connection.GetRaw(
            '/servers/' + server_id + '/user_data/ssh-host-fingerprints')

    @retry(stop_max_attempt_number=50,
           wait_exponential_multiplier=500,
           wait_exponential_max=5*60000,
           retry_on_exception=_IsHTTPError)
    def WaitForServer(self, server_id):
        self.GetServer(server_id)
