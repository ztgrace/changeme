import base64
import random
from requests import session
from .scanner import Scanner
import re
from selenium import webdriver
from time import sleep
try:
    # Python 3
    from urllib.parse import urlencode, urlparse
except ImportError:
    # Python 2
    from urllib import urlencode
    from urlparse import urlparse

HEADERS_USERAGENTS = [
    'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
    'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
    'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
    'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
    'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
    'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
    'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
    'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
    'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
    'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
    'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51'
]


def get_useragent():
    return random.choice(HEADERS_USERAGENTS)


class HTTPGetScanner(Scanner):

    def __init__(self, cred, target, username, password, config, cookies):
        super(HTTPGetScanner, self).__init__(cred, target, config, username, password)
        self.cred = cred
        self.config = config
        self.cookies = cookies
        self.headers = dict()
        self.request = session()
        self.response = None

        headers = self.cred['auth'].get('headers', dict())
        custom_ua = False
        if headers:
            for h in headers:
                self.headers.update(h)
                if not custom_ua and any(k.lower() == 'user-agent' for k in h):
                    custom_ua = True

        # If set, take user agent from CLI args, otherwise, pick a random
        # one if not provided in the cred file.
        if self.config.useragent:
            self.headers.update(self.config.useragent)
        elif not custom_ua:
            self.headers.update({'User-Agent': get_useragent()})

        # make the cred have only one u:p combo
        self.cred['auth']['credentials'] = [{'username': self.username, 'password': self.password}]

    def __reduce__(self):
        return self.__class__, (self.cred, self.target, self.username, self.password, self.config, self.cookies)

    def scan(self):
        try:
            self._make_request()
        except Exception as e:
            self.logger.error('Failed to connect to %s' % self.target)
            self.logger.debug('Exception: %s: %s' % (type(e).__name__, e.__str__().replace('\n', '|')))
            return None

        if self.response.status_code == 429:
            self.warn('Status 429 received. Sleeping for %d seconds and trying again' % self.config.delay)
            sleep(self.config.delay)
            try:
                self._make_request()
            except Exception as e:
                self.logger.error('Failed to connect to %s' % self.target)

        return self.check_success()

    def check_success(self):
        match = False
        success = self.cred['auth']['success']

        if self.cred['auth'].get('base64', None):
            self.username = base64.b64decode(self.cred.username)
            self.password = base64.b64decode(self.cred.password)

        if success.get('status') == self.response.status_code:
            self.logger.debug('%s matched %s success status code %s' % (self.target, self.cred['name'], self.response.status_code))
            if success.get('body'):
                for string in success.get('body'):
                    if re.search(string, self.response.text, re.IGNORECASE):
                        self.logger.debug('%s matched %s success body text %s' % (self.target, self.cred['name'], success.get('body')))
                        match = True
                        break
            else:
                match = True

        if match:
            self.logger.critical('[+] Found %s default cred %s:%s at %s' %
                                 (self.cred['name'], self.username, self.password, self.target))
            evidence = ''
            if self.config.output is not None:
                try:
                    evidence = self._screenshot(self.target)
                except Exception as e:
                    self.logger.error("Error gathering screenshot for %s" % self.target)
                    self.logger.debug('Exception: %s: %s' % (type(e).__name__, e.__str__().replace('\n', '|')))

            return {'name': self.cred['name'],
                    'username': self.username,
                    'password': self.password,
                    'target': self.target,
                    'evidence': evidence}
        else:
            self.logger.info('Invalid %s default cred %s:%s at %s' %
                             (self.cred['name'], self.username, self.password, self.target))
            return False

    def _check_fingerprint(self):
        self.logger.debug("_check_fingerprint")
        self.request = session()
        self.response = self.request.get(self.target,
                                         timeout=self.config.timeout,
                                         verify=False,
                                         proxies=self.config.proxy,
                                         cookies=self.fingerprint.cookies,
                                         headers=self.fingerprint.headers)
        self.logger.debug('_check_fingerprint', '%s - %i' % (self.target, self.response.status_code))
        return self.fingerprint.match(self.response)

    def _make_request(self):
        self.logger.debug("_make_request")
        data = self.render_creds(self.cred)
        qs = urlencode(data)
        url = "%s?%s" % (self.target, qs)
        self.logger.debug("url: %s" % url)
        self.response = self.request.get(self.target,
                                         verify=False,
                                         proxies=self.config.proxy,
                                         timeout=self.config.timeout,
                                         headers=self.headers,
                                         cookies=self.cookies)

    def render_creds(self, candidate, csrf=None):
        """
            Return a list of dicts with post/get data and creds.

            The list of dicts have a data element and a username and password
            associated with the data. The data will either be a dict if its a
            regular GET or POST and a string if its a raw POST.
        """
        b64 = candidate['auth'].get('base64', None)
        type = candidate['auth'].get('type')
        config = None
        if type == 'post':
            config = candidate['auth'].get('post', None)
        if type == 'get':
            config = candidate['auth'].get('get', None)

        if not type == 'raw_post':
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

                data_to_send = dict(list(data.items()) + list(cred_data.items()))
                return data_to_send
        else:  # raw post
            return None

    def _get_parameter_dict(self, auth):
        params = dict()
        data = auth.get('post', auth.get('get', None))
        for k in list(data.keys()):
            if k not in ('username', 'password', 'url'):
                params[k] = data[k]

        return params

    @staticmethod
    def get_base_url(req):
        parsed = urlparse(req)
        url = "%s://%s" % (parsed[0], parsed[1])
        return url

    def _screenshot(self, target):
        self.logger.debug("Screenshotting %s" % self.target)
        # Set up the selenium webdriver
        # This feels like it will have threading issues
        for key, value in self.response.request.headers.items():
            capability_key = 'phantomjs.page.customHeaders.{}'.format(key)
            webdriver.DesiredCapabilities.PHANTOMJS[capability_key] = value

        if self.config.proxy:
            webdriver.DesiredCapabilities.PHANTOMJS['proxy'] = {
                    "httpProxy": self.config.proxy['http'].replace('http://', ''),
                    "ftpProxy": self.config.proxy['http'].replace('http://', ''),
                    "sslProxy": self.config.proxy['http'].replace('http://', ''),
                    "noProxy":None,
                    "proxyType":"MANUAL",
                    "autodetect":False
            }
        driver = webdriver.PhantomJS()
        driver.set_page_load_timeout(int(self.config.timeout) - 0.1)
        driver.set_window_position(0, 0)
        driver.set_window_size(850, 637.5)
        for cookie in self.response.request._cookies.items():
            self.logger.debug("Adding cookie: %s:%s" % cookie)
            driver.add_cookie({'name': cookie[0],
                               'value': cookie[1],
                               'path': '/',
                               'domain': self.target.host
            })

        try:
            driver.get(str(self.target))
            driver.save_screenshot('screenshot.png')
            evidence = driver.get_screenshot_as_base64()
            driver.quit()
        except Exception as e:
            self.logger.error('Error getting screenshot for %s' % self.target)
            self.logger.debug('Exception: %s: %s' % (type(e).__name__, e.__str__().replace('\n', '|')))
            evidence = ""

        return evidence

