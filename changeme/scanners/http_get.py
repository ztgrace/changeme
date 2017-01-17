import base64
from scanner import Scanner
import re
import urllib
from urlparse import urlparse


class HTTPGetScanner(Scanner):

    def __init__(self, cred, target, username, password, config, session):
        super(HTTPGetScanner, self).__init__(cred, target, config)
        self.cred = cred
        self.config = config
        self.request = session
        self.response = None
        self.url = target
        self.username = username
        self.password = password

        # make the cred have only one u:p combo
        self.cred['auth']['credentials'] = [{'username': self.username, 'password': self.password}]

    def scan(self):
        self.debug("scan")
        self._make_request()
        # TODO handle 429 requests
        return self.check_success()

        return False

    def check_success(self):
        self.debug("check_success")
        match = False
        success = self.cred['auth']['success']
        if self.cred['auth'].get('base64', None):
            username = base64.b64decode(self.cred.username)
            password = base64.b64decode(self.cred.password)

        if success.get('status') == self.response.status_code:
            if success.get('body'):
                for string in success.get('body'):
                    if re.search(string, self.response.text, re.IGNORECASE):
                        match = True
                        break
            else:
                match = True

        else:
            print "status code didn't match %s/%s" % (success.get('status'), self.response.status_code)

        if match:
            self.config.logger.critical('[+] Found %s default cred %s:%s at %s' %
                            (self.cred['name'], self.username, self.password, self.url))
            return self.cred['name'], self.username, self.password, self.request
        else:
            self.config.logger.info( '[check_success] Invalid %s default cred %s:%s at %s' %
                         (self.cred['name'], self.username, self.password, self.url))
            return False

    def _check_fingerprint(self):
        self.debug("_check_fingerprint")
        self.response = self.request.get(self.url,
                                         timeout=self.config.timeout,
                                         verify=False,
                                         proxies=self.config.proxy,
                                         cookies=self.fingerprint.cookies,
                                         headers=self.fingerprint.headers)
        self.debug('_check_fingerprint', '%s - %i' % (self.url, self.response.status_code))
        return self.fingerprint.match(self.response)

    def _make_request(self):
        self.debug("_make_request")
        data = self.render_creds(self.cred, self.csrf)
        qs = urllib.urlencode(data)
        url = "%s?%s" % (self.url, qs)
        self.debug("[check_http] url: %s" % url)
        self.response = self.request.get(self.url,
                                         verify=False,
                                         proxies=self.config['proxy'],
                                         timeout=self.config['timeout'],
                                         headers=self.config['headers']
                                         )

    def _build_headers(self):
        self.cred['']

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
