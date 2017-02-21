from scanner import Scanner
import random
from time import sleep
import re
import base64
import urllib
from urlparse import urlparse
import requests
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from copy import copy, deepcopy
from changeme.fingerprint import Fingerprint
# from lxml import html
from xml.etree import ElementTree as etree


class HTTP(Scanner):

    def __init__(self, data, target, config):
        super(HTTP, self).__init__(data, target, config)

        self.config = config
        self.target = target
        self.useragent = {'User-Agent': config.useragent if config.useragent else self._get_useragent()}
        self.urls = data['auth']['url']
        self.headers = data['auth'].get('headers', None)
        self.isb64 = data['auth'].get('base64', None)
        self.success = data['auth']['success']
        self.param = self._get_parameter_dict(data['auth'])
        self.config_request = data['auth'].get('post', data['auth'].get('get', data['auth'].get('raw_post', None)))
        self.cookie = data['auth'].get('sessionid', False)
        self.csrf_name = data['auth'].get('csrf', False)
        self.sessionid_name = data['auth'].get('sessionid', False)
        self.password_found = list()

        if config.ssl:
            self.ssl = 'https'
        else:
            self.ssl = 'http'

        self.fingerprint = Fingerprint(self.name, config, data['fingerprint'])

    def scan(self):

        self.logger.debug("[%s][scan]" % self._class_name())

        headers = self.useragent
        if self.fingerprint.headers:
            headers.update(fp.headers)
            self.logger.debug("merged headers: %s" % headers)

        # if fingerprint matches with the target, realize scan
        if self.fingerprint.http_fingerprint(headers, self.ssl, self.target, str(self.port)):
            
            self.logger.debug('[do_scan] Fingerprint matches successfully')

            for u in self.urls:
                url = '%s://%s:%s%s' % (self.ssl, self.target, str(self.port), u)
                s = requests.Session()

                try:
                    res = s.get(url, timeout=self.config.timeout, verify=False, proxies=self.config.proxy, cookies=self.fingerprint.cookies, headers=headers)
                except Exception as e:
                    self.logger.debug('[do_scan] Failed to connect to %s' % url)
                    self.logger.debug(e)
                    continue

                self.logger.debug('[do_scan] %s - %i' % (url, res.status_code))
       
                # Only scan if a sessionid is required and we can get it
                sessionid = self._get_session_id(res)
                if self.sessionid_name and not sessionid:
                    self.logger.debug("[do_scan] Missing required sessionid")
                    continue

                # Only scan if a csrf token is required and we can get it
                csrf = self._get_csrf_token(res)
                if self.csrf_name and not csrf:
                    self.logger.debug("[do_scan] Missing required csrf")
                    continue

                # Ready to scan for default creds
                self._check_http(url, s, sessionid, csrf)
                break

        return self.password_found


    def _get_useragent(self):
        headers_useragents = [
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
        return random.choice(headers_useragents)

    def _get_base_url(self, req):
        parsed = urlparse(req)
        url = "%s://%s" % (parsed[0], parsed[1])
        return url

    def _get_parameter_dict(self, auth):
        params = dict()
        data = auth.get('post', auth.get('get', ''))
        for k in data:
            if k not in ('username', 'password', 'url'):
                params[k] = data[k]
        return params

    def _get_session_id(self, res):
        self.logger.debug("[get_session_id] cookie: %s" % self.cookie)
        if self.cookie:
            try:
                value = res.cookies[self.cookie]
                self.logger.debug('[get_session_id] cookie value: %s' % value)
            except:
                self.logger.error("[get_session_id] failed to get %s cookie from %s" % (self.cookie, res.url))
                return False
            return {self.cookie: value}
        else:
            self.logger.debug('[get_session_id] no cookie')
            return False

    def _get_csrf_token(self, res):
        csrf = False
        if self.csrf_name:
            # modification of the lib used (xml instead of lxml)
            # tree = html.fromstring(res.content)

            # to test again, to be sure this xpath function works...
            parser = etree.XMLParser(encoding="utf-8")
            try:
                root = etree.fromstring(res.content, parser=parser)
                # csrf = tree.xpath('//input[@name="%s"]/@value' % self.csrf_name)[0]
                for elem in root.iterfind('//input[@name="%s"]/@value' % self.csrf_name):
                    if elem.text is not None:
                        csrf = elem.text
                        break
            except:
                self.logger.error("[get_csrf_token] failed to get CSRF token %s in %s" % (str(self.csrf_name), str(res.url)))
                return False
            self.logger.debug('[get_csrf_token] got CSRF token %s: %s' % (self.csrf_name, csrf))
        return csrf


    def _render_creds(self, csrf):
        """
            Return a list of dicts with post/get data and creds.

            The list of dicts have a data element and a username and password
            associated with the data. The data will either be a dict if its a
            regular GET or POST and a string if its a raw POST.
        """
        posts = list()
        if self.type == 'basic_auth':
            for cred in self.creds:
                posts.append({
                    'username': cred['username'],
                    'password': cred['password']
                })
        elif not self.type == 'raw_post':
            data = self.param
            
            if csrf:
                data[self.csrf_name] = csrf

            for cred in self.creds:
                cred_data = {}
                username = ""
                password = ""
                if self.isb64:
                    username = base64.b64encode(cred['username'])
                    password = base64.b64encode(cred['password'])
                else:
                    username = cred['username']
                    password = cred['password']

                cred_data[self.config_request['username']] = username
                cred_data[self.config_request['password']] = password

                data_to_send = dict(data.items() + cred_data.items())
                posts.append({
                    'data': data_to_send,
                    'username': username,
                    'password': password
                })
        else:  # raw post
            for cred in self.creds:
                posts.append({
                    'data': cred['raw'],
                    'username': cred['username'],
                    'password': cred['password'],
                })

        return posts


    def _send_request(self, session, url, cred, sessionid, headers):
        try:
            if self.type == 'basic_auth':
                res = session.get(
                    url,
                    auth=HTTPBasicAuth(cred['username'], cred['password']),
                    verify=False,
                    proxies=self.config.proxy,
                    timeout=self.config.timeout,
                    headers=headers
                )
            elif self.type == 'post' or self.type == 'raw_post':
                res = session.post(
                    url,
                    cred['data'],
                    cookies=sessionid,
                    verify=False,
                    proxies=self.config.proxy,
                    timeout=self.config.timeout,
                    headers=headers,
                )
            else:
                qs = urllib.urlencode(cred['data'])
                url = "%s?%s" % (url, qs)
                res = session.get(
                    url,
                    cookies=sessionid,
                    verify=False,
                    proxies=self.config.proxy,
                    timeout=self.config.timeout,
                    headers=headers,
                )
            return True, res
        except Exception as e:
            self.logger.error("[check_http] Failed to connect to %s" % url)
            self.logger.debug("[check_http] Exception: %s" % e.__str__().replace('\n', '|'))
            return False


    def _check_http(self, req, session, sessionid=False, csrf=False):
        headers = dict()
        delay = self.config.delay

        if self.headers:
            self.logger.debug('[check_http] headers: %s' % self.headers)
            for head in self.headers:
                headers.update(head)
            headers.update(self.useragent)
        else:
            headers = self.useragent

        # Copy the session so successful creds don't affect other
        orig_session = deepcopy(session)
        rendered = self._render_creds(csrf)
        for cred in rendered:
            self.logger.debug('[check_http] %s - %s:%s' % (self.name, cred['username'], cred['username'],))

            for u in self.urls:
                url = self._get_base_url(req) + u
                self.logger.debug("[check_http] url: %s" % url)

                # restore the original session
                session = deepcopy(orig_session)
                ok, res = self._send_request(session, url, cred, sessionid, headers)
                if not ok:
                    continue

                self.logger.debug('[check_http] res.status_code: %i' % res.status_code)

                # Adding sleep and try again if 429 status code received.
                # Response code 429 is too many requests.  Some appliances or WAFs may respond this way if
                # There are too many requests from the same source in a certain amount of time.
                if res.status_code == 429:
                    i = 0
                    while i < 2 and res.status_code == 429: #Trying two more times for a total of three times
                        if i != 0:
                            delay = delay + .5
                        self.logger.warn('[check_http] Status 429 received. Sleeping for %d miliseconds and trying again' % (delay / .001))
                        sleep(delay)
                        
                        session = deepcopy(orig_session)
                        res = self._send_request(session, url, cred, sessionid, headers)
                        if not res:
                            continue
                        
                        self.logger.error('[check_http] res.status_code: %i' % res.status_code)
                        self.logger.debug('[check_http] res.text: %s' % res.text)
                        i += 1

                if self._check_success(req, res, cred['username'], cred['password']):
                    self.password_found.append(
                        {
                            'name': self.name, 
                            'username': cred['username'], 
                            'pasword': cred['password'], 
                            'url': req
                        }
                    )
                    # break
            delay = self.config.delay

    def _check_success(self, req, res, username, password):
        match = False
        if self.isb64:
            username = base64.b64decode(username)
            password = base64.b64decode(password)

        if self.success.get('status') == res.status_code:
            if self.success.get('body'):
                for string in self.success.get('body'):
                    if re.search(string, res.text, re.IGNORECASE):
                        match = True
                        break
            else:
                match = True

        if match:
            self.logger.critical('[+] Found %s default cred %s:%s at %s' % (self.name, username, password, req))
            return True
        
        self.logger.info( '[check_success] Invalid %s default cred %s:%s at %s' % (self.name, username, password, req))
        return False
