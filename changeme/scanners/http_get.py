import base64
import logging
from requests import session
from scanner import Scanner
import re
from time import sleep
import urllib
from urlparse import urlparse


class HTTPGetScanner(Scanner):

    def __init__(self, cred, target, username, password, config, cookies):
        super(HTTPGetScanner, self).__init__(cred, target, config)
        self.cred = cred
        self.config = config
        self.cookies = cookies
        self.headers = dict()
        self.request = session()
        self.response = None
        self.password = password
        self.url = target
        self.username = username

        headers = self.cred['auth'].get('headers', dict())
        if headers:
            for h in headers:
                self.headers.update(h)
        self.headers.update(self.config.useragent)


        # make the cred have only one u:p combo
        self.cred['auth']['credentials'] = [{'username': self.username, 'password': self.password}]

    def scan(self):
        try:
            self._make_request()
        except Exception as e:
            self.logger.error('Failed to connect to %s' % self.url)
            self.logger.debug('Exception: %s' % e.__str__().replace('\n', '|'))
            return None

        if self.response.status_code == 429:
            self.warn('Status 429 received. Sleeping for %d seconds and trying again' % self.config.delay)
            sleep(self.config.delay)
            try:
                self._make_request()
            except Exception as e:
                self.logger.error('Failed to connect to %s' % self.url)

        return self.check_success()

    def check_success(self):
        match = False
        success = self.cred['auth']['success']

        if self.cred['auth'].get('base64', None):
            self.username = base64.b64decode(self.cred.username)
            self.password = base64.b64decode(self.cred.password)

        if success.get('status') == self.response.status_code:
            if success.get('body'):
                for string in success.get('body'):
                    if re.search(string, self.response.text, re.IGNORECASE):
                        match = True
                        break
            else:
                match = True

        if match:
            self.logger.critical('[+] Found %s default cred %s:%s at %s' %
                            (self.cred['name'], self.username, self.password, self.url))

            return {'name': self.cred['name'],
                    'username': self.username,
                    'password': self.password,
                    'url': self.url}
        else:
            self.logger.info('Invalid %s default cred %s:%s at %s' %
                         (self.cred['name'], self.username, self.password, self.url))
            return False

    def _check_fingerprint(self):
        self.logger.debug("_check_fingerprint")
        self.request = session()
        self.response = self.request.get(self.url,
                                         timeout=self.config.timeout,
                                         verify=False,
                                         proxies=self.config.proxy,
                                         cookies=self.fingerprint.cookies,
                                         headers=self.fingerprint.headers)
        self.logger.debug('_check_fingerprint', '%s - %i' % (self.url, self.response.status_code))
        return self.fingerprint.match(self.response)

    def _make_request(self):
        self.logger.debug("_make_request")
        data = self.render_creds(self.cred, self.csrf)
        qs = urllib.urlencode(data)
        url = "%s?%s" % (self.url, qs)
        self.logger.debug("url: %s" % url)
        self.response = self.request.get(self.url,
                                         verify=False,
                                         proxies=self.config.proxy,
                                         timeout=self.config.timeout,
                                         headers=self.headers,
                                         cookies=self.cookies)

    def render_creds(self, candidate, csrf):
        """
            Return a list of dicts with post/get data and creds.

            The list of dicts have a data element and a username and password
            associated with the data. The data will either be a dict if its a
            regular GET or POST and a string if its a raw POST.
        """
        b64 = candidate['auth'].get('base64', None)
        config = candidate['auth'].get('post', candidate['auth'].get(
            'get', candidate['auth'].get('raw_post', None)))

        if not candidate['auth']['type'] == 'raw_post':
            data = self._get_parameter_dict(candidate['auth'])

            if csrf:
                csrf_field = candidate['auth']['csrf']
                data[csrf_field] = csrf

            for cred in candidate['auth']['credentials']:
                cred_data = {}
                username = ""
                password = ""
                if b64:
                    username = base64.b64encode(cred['username'])
                    password = base64.b64encode(cred['password'])
                else:
                    username = cred['username']
                    password = cred['password']

                cred_data[config['username']] = username
                cred_data[config['password']] = password

                data_to_send = dict(data.items() + cred_data.items())
                return data_to_send
        else:  # raw post
            return candidate['auth']['credential']['raw']

    def _get_parameter_dict(self, auth):
        params = dict()
        data = auth.get('post', auth.get('get', None))
        for k in data.keys():
            if k not in ('username', 'password', 'url'):
                params[k] = data[k]

        return params

    @staticmethod
    def get_base_url(req):
        parsed = urlparse(req)
        url = "%s://%s" % (parsed[0], parsed[1])
        return url
