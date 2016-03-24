#!/usr/bin/env python
# nosetests -v -s --with-coverage --cover-erase --cover-package=changeme tests/*.py

import changeme
from nose.tools import *
import yaml
import logging
import requests
import responses
import re
import random
from time import sleep


class mock:
    tomcat_fp = {
        'method': responses.GET,
        'url': 'http://127.0.0.1:8080/manager/html',
        'status': 401,
        'adding_headers': {
            'Server': 'Apache-Coyote/1.1',
            'WWW-Authenticate': 'Basic realm="Tomcat Manager Application'}
    }

    tomcat_auth = {
        'method': responses.GET,
        'url': 'http://127.0.0.1:8080/manager/html',
        'status': 200,
        'body': '<font size="+2">Tomcat Web Application Manager</font>',
        'adding_headers': {'Server': 'Apache-Coyote/1.1'}
    }

    jboss_fp = {
        'method': responses.GET,
        'url': 'http://127.0.0.1:8080/admin-console/login.seam',
        'status': 200,
        'body': '<p>Welcome to the JBoss AS 6 Admin Console.</p><input name="javax.faces.ViewState" value="foobar" />',
        'adding_headers': {
            'Server': 'Apache-Coyote/1.1',
            'Set-Cookie': 'JSESSIONID=foobar'
            }
    }

    jboss_auth = {
        'method': responses.POST,
        'url': 'http://127.0.0.1:8080/admin-console/login.seam',
        'status': 200,
        'body': '<a>Logout</a>',
        'adding_headers': {'Server': 'Apache-Coyote/1.1'}
    }

    idrac_fp = {
        'method': responses.GET,
        'url': 'https://127.0.0.1/login.html',
        'status': 200,
        'body': '<title>Integrated Dell Remote Access Controller</title>',
        'adding_headers': {
            'Server': 'Mbedthis-Appweb/2.4.2',
            'Content-type': 'text/xml',
            'Set-Cookie': '_appwebSessionId_=dffaac7c4fb4e3c4cbd46d3691aeb40f;',
        },
        'body': '<title>Integrated Dell Remote Access Controller 6 - Express</title>',
    }

    idrac_auth = {
        'method': responses.POST,
        'url': 'https://127.0.0.1/data/login',
        'status': 200,
        'body': '<title>Integrated Dell Remote Access Controller</title>',
        'adding_headers': {
            'Server': 'Mbedthis-Appweb/2.4.2',
            'Content-type': 'text/xml',
            'Set-Cookie': '_appwebSessionId_=dffaac7c4fb4e3c4cbd46d3691aeb40f',
        },
        'body': '<? xml version="1.0" encoding="UTF-8"?> <root> <status>ok</status> <authResult>0</authResult> <forwardUrl>index.html</forwardUrl> </root>'
    }

    zabbix_fp = {
        'method': responses.GET,
        'url': 'http://127.0.0.1/zabbix/index.php',
        'status': 200,
        'body': 'by Zabbix SIA',
    }

    zabbix_auth = {
        'method': responses.POST,
        'url': 'http://127.0.0.1/zabbix/index.php',
        'status': 200,
        'body': '<a>Logout</a>',
    }

    zabbix_fail = {
        'method': responses.POST,
        'url': 'http://127.0.0.1/zabbix/index.php',
        'status': 200,
        'body': 'foobar',
    }

    ipcamera_fp = {
        'method': responses.GET,
        'url': 'http://127.0.0.1:81/',
        'status': 200,
        'body': 'GetXml("login.xml?"+param,OnLoginAckOK,OnLoginAckFail);'
    }

    ipcamera_auth = {
        'method': responses.GET,
        'url': 'http://127.0.0.1:81/login.xml',
        'status': 200,
        'body': '<?xml version="1.0" encoding="UTF-8" ?><Result><Success>1</Success><UserLevel>0</UserLevel><UserGroup>Admin</UserGroup></Result>'
    }


class TestChangeme:

    @classmethod
    def setup_class(cls):
        changeme.logger = changeme.setup_logging(True, True, None)

    def __init__(self):
        self.creds = None
        self.tomcat_yaml = 'creds/apache_tomcat.yml'
        self.tomcat_name = 'Apache Tomcat'
        self.jboss_name = 'JBoss AS 6'
        self.idrac_name = 'Dell iDRAC'

        self.config = {
            'threads': 1,
            'timeout': 2,
            'proxy': None,
            'fingerprint': False}

    def setUp(self):
        self.creds = changeme.load_creds()

    def tearDown(self):
        self.creds = None

    def get_cred(self, name):
        for i in self.creds:
            if i['name'] == name:
                return i

    """
        is_yaml tests
    """
    def test_is_yaml_true(self):
        assert changeme.is_yaml(self.tomcat_yaml) is True

    def test_is_yaml_false(self):
        assert changeme.is_yaml("/etc/hosts") is False

    """
        parse_yaml tests
    """
    def test_parse_yaml_good(self):
        assert changeme.parse_yaml(self.tomcat_yaml)

    @raises(yaml.scanner.ScannerError)
    def test_parse_yaml_bad(self):
        assert changeme.parse_yaml("/etc/hosts")

    """
        load_creds
    """
    def test_load_creds_good(self):
        changeme.logger = changeme.setup_logging(False, False, None)
        changeme.load_creds()

    """
        validate_cred
    """
    def test_validate_cred(self):

        cred = self.creds[random.randrange(0, len(self.creds))]
        key = random.choice(cred.keys())
        if key in ('auth', 'category', 'contributor', 'default_port', 'fingerprint', 'name', 'ssl'):
            cred.pop(key)

        assert changeme.validate_cred(cred, "test_validate_cred") is False

    """
        setup_logging tests
    """
    def test_setup_logging(self):
        logger = changeme.setup_logging(False, False, None)
        assert logger.isEnabledFor(logging.WARNING)

    def test_setup_logging_verbose(self):
        logger = changeme.setup_logging(True, False, None)
        assert logger.isEnabledFor(logging.INFO)

    def test_setup_logging_debug(self):
        logger = changeme.setup_logging(False, True, None)
        assert logger.isEnabledFor(logging.INFO)
        assert logger.isEnabledFor(logging.DEBUG)

    def test_setup_logging_file(self):
        fh = False
        logger = changeme.setup_logging(False, False, "/tmp/foo.log")
        for i in logger.handlers:
            if isinstance(i, logging.FileHandler):
                fh = True
        assert fh

    """
        get_fingerprint_matches
    """
    @responses.activate
    def test_get_fingerprint_matches_tomcat(self):
        responses.add(** mock.tomcat_fp)
        res = requests.get(mock.tomcat_fp['url'])

        # Verify the response came back correctly
        assert res.status_code == 401
        assert res.headers.get('WWW-Authenticate')

        matches = changeme.get_fingerprint_matches(res, self.creds)

        matched = False
        for i in matches:
            if i['name'] == self.tomcat_name:
                matched = True
        assert matched

    @responses.activate
    @raises(requests.exceptions.ConnectionError)
    def test_get_fingerprint_matches_tomcat_fail(self):
        responses.add(** mock.jboss_fp)
        res = requests.get(mock.tomcat_fp['url'])

        matches = changeme.get_fingerprint_matches(res, self.creds)

        for i in matches:
            if i['name'] == self.tomcat_name:
                matched = True
            else:
                matched = False
        assert not matched

    @responses.activate
    def test_get_fingerprint_matches_jboss(self):
        responses.add(** mock.jboss_fp)
        res = requests.get(mock.jboss_fp['url'])

        # Verify the response came back correctly
        assert res.status_code == 200
        assert "Welcome to the JBoss AS 6 Admin Console" in res.text

        matches = changeme.get_fingerprint_matches(res, self.creds)

        matched = False
        for i in matches:
            if i['name'] == self.jboss_name:
                matched = True
        assert matched

    @responses.activate
    def test_get_fingerprint_matches_jboss_fail_body(self):
        orig = mock.jboss_fp['body']
        mock.jboss_fp['body'] = "foobar"
        responses.add(** mock.jboss_fp)
        res = requests.get(mock.jboss_fp['url'])
        mock.jboss_fp['body'] = orig

        matches = changeme.get_fingerprint_matches(res, self.creds)

        matched = False
        for i in matches:
            if i['name'] == self.jboss_name:
                matched = True
            else:
                matched = False
        assert not matched

    """
        check_basic_auth
    """
    @responses.activate
    def test_check_basic_auth_tomcat(self):
        responses.add(** mock.tomcat_auth)

        cred = None
        for i in self.creds:
            if i['name'] == self.tomcat_name:
                cred = i

        assert cred['name'] == self.tomcat_name

        matches = changeme.check_basic_auth(mock.tomcat_fp['url'], cred, False, False, None)
        assert len(matches) > 0

    @responses.activate
    def test_check_basic_auth_tomcat_fail(self):
        responses.add(** mock.tomcat_fp)

        cred = self.get_cred(self.tomcat_name)
        assert cred['name'] == self.tomcat_name

        changeme.logger = changeme.setup_logging(False, False, None)
        matches = changeme.check_basic_auth(mock.tomcat_fp['url'], cred, False, False)
        assert len(matches) == 0

    """
        check_form
    """
    @responses.activate
    def test_check_form_jboss(self):
        responses.add(** mock.jboss_auth)

        cred = self.get_cred(self.jboss_name)
        assert cred['name'] == self.jboss_name

        matches = changeme.check_form(
                            mock.jboss_fp['url'],
                            cred,
                            {'JSESSIONID': 'foobar'},
                            'foobar')

        assert len(matches) > 0

    @responses.activate
    def test_check_form_jboss_fail(self):
        responses.add(** mock.tomcat_fp)

        cred = self.get_cred(self.jboss_name)
        assert cred['name'] == self.jboss_name

        matches = changeme.check_form(
                            mock.jboss_fp['url'],
                            cred,
                            {'JSESSIONID': 'foobar'},
                            'foobar')

        assert matches is None

    @responses.activate
    def test_check_form_zabbix(self):
        responses.add(** mock.zabbix_auth)

        cred = self.get_cred('Zabbix')
        assert cred['name'] == 'Zabbix'

        matches = changeme.check_form(mock.zabbix_auth['url'], cred, False, False)
        assert len(matches) > 0

    @responses.activate
    def test_check_form_zabbix_fail(self):
        responses.add(** mock.zabbix_fail)

        cred = self.get_cred('Zabbix')
        assert cred['name'] == 'Zabbix'

        matches = changeme.check_form(mock.zabbix_auth['url'], cred, False, False)
        assert len(matches) == 0

    """
        get_csrf_token
    """
    @responses.activate
    def test_get_csrf_token(self):
        responses.add(** mock.jboss_fp)
        res = requests.get(mock.jboss_fp['url'])

        cred = self.get_cred(self.jboss_name)
        assert cred['name'] == self.jboss_name

        csrf = changeme.get_csrf_token(res, cred)
        assert csrf == 'foobar'

    @responses.activate
    def test_get_csrf_token_fail(self):
        orig = mock.jboss_fp['body']
        mock.jboss_fp['body'] = "foobar"
        responses.add(** mock.jboss_fp)
        mock.jboss_fp['body'] = orig

        res = requests.get(mock.jboss_fp['url'])

        cred = self.get_cred(self.jboss_name)
        assert cred['name'] == self.jboss_name

        csrf = changeme.get_csrf_token(res, cred)
        assert csrf is False

    @responses.activate
    def test_get_csrf_token_no_token(self):
        responses.add(** mock.zabbix_fp)
        res = requests.get(mock.zabbix_fp['url'])

        cred = self.get_cred('Zabbix')
        assert cred['name'] == 'Zabbix'

        csrf = changeme.get_csrf_token(res, cred)
        assert csrf is False

        matches = changeme.get_fingerprint_matches(res, self.creds)
        assert len(matches) == 1

    """
        get_session_id
    """
    @responses.activate
    def test_get_session_id(self):
        responses.add(** mock.jboss_fp)
        res = requests.get(mock.jboss_fp['url'])

        cred = self.get_cred(self.jboss_name)
        assert cred['name'] == self.jboss_name

        sessionid = changeme.get_session_id(res, cred)
        assert sessionid['JSESSIONID'] == 'foobar'

    @responses.activate
    def test_get_session_id_fail(self):
        orig = mock.jboss_fp['adding_headers']
        mock.jboss_fp['adding_headers']['Set-Cookie'] = 'foo=bar'

        responses.add(** mock.jboss_fp)
        res = requests.get(mock.jboss_fp['url'])

        mock.jboss_fp['adding_headers']['Set-Cookie'] = "JSESSIONID=foobar"

        cred = self.get_cred(self.jboss_name)
        assert cred['name'] == self.jboss_name

        sessionid = changeme.get_session_id(res, cred)
        assert sessionid is False

    @responses.activate
    def test_get_session_id_no_id(self):
        responses.add(** mock.tomcat_fp)
        res = requests.get(mock.tomcat_fp['url'])

        cred = self.get_cred(self.tomcat_name)
        assert cred['name'] == self.tomcat_name

        sessionid = changeme.get_session_id(res, cred)
        assert sessionid is False

    @responses.activate
    def test_scan(self):
        responses.add(** mock.tomcat_fp)
        responses.add(** mock.jboss_fp)

        urls = list()
        urls.append(mock.tomcat_fp['url'])
        urls.append(mock.jboss_fp['url'])
        urls.append("http://192.168.0.99:9999/foobar/index.php")

        changeme.scan(urls, self.creds, self.config)

    @raises(SystemExit)
    def test_dry_run(self):
        urls = list()
        urls.append(mock.tomcat_fp['url'])
        urls.append(mock.jboss_fp['url'])
        changeme.dry_run(urls)

    def test_build_target_list(self):
        changeme.targets = ["127.0.0.1"]
        urls = changeme.build_target_list(changeme.targets, self.creds, None, None)
        assert isinstance(urls, list)

        urls = changeme.build_target_list(changeme.targets, self.creds, None, 'web')
        assert isinstance(urls, list)
        assert "http://127.0.0.1:8080/manager/html" in urls

        urls = changeme.build_target_list(changeme.targets, self.creds, self.tomcat_name, None)
        apache_cred = self.get_cred(self.tomcat_name)
        paths = apache_cred['fingerprint']['url']

        match = True
        for url in urls:
            path = re.search("https?://[a-zA-Z0-9\.]+:?[0-9]{0,5}(.*)$", url).group(1)
            if path not in paths:
                assert False
                return

    @responses.activate
    def test_do_scan(self):
        responses.add(** mock.tomcat_fp)
        responses.add(** mock.jboss_fp)

        changeme.do_scan(mock.tomcat_fp['url'], self.creds, self.config)
        sleep(2)
        changeme.do_scan(mock.jboss_fp['url'], self.creds, self.config)

    @responses.activate
    def test_do_scan_fail(self):
        responses.add(** mock.tomcat_fp)
        changeme.do_scan(mock.jboss_fp['url'], self.creds, self.config)

    @responses.activate
    def test_idrac_fp(self):
        responses.add(** mock.idrac_fp)
        res = requests.get(mock.idrac_fp['url'])

        matches = changeme.get_fingerprint_matches(res, self.creds)

        assert len(matches) == 1
        assert matches[0]['name'] == self.idrac_name

    @responses.activate
    def test_do_scan_idrac(self):
        """
            This test will makes sure the regex in
            iDRAC success body works
        """
        responses.add(** mock.idrac_fp)
        responses.add(** mock.idrac_auth)

        changeme.logger = changeme.setup_logging(True, True, None)
        matches = changeme.do_scan(mock.idrac_fp['url'], self.creds, self.config)

        assert len(matches) == 1
        assert matches[0]['name'] == self.idrac_name

    @responses.activate
    def test_do_scan_missing_sessionid(self):
        orig = mock.jboss_fp['adding_headers']
        mock.jboss_fp['adding_headers'] = None
        responses.add(** mock.jboss_fp)
        responses.add(** mock.jboss_auth)

        matches = changeme.do_scan(mock.jboss_fp['url'], self.creds, self.config)
        mock.jboss_fp['adding_headers'] = orig

        assert len(matches) == 0

    @responses.activate
    def test_do_scan_missing_csrf(self):
        orig = mock.jboss_fp['body']
        mock.jboss_fp['body'] = '<p>Welcome to the JBoss AS 6 Admin Console.</p>'
        responses.add(** mock.jboss_fp)
        responses.add(** mock.jboss_auth)

        matches = changeme.do_scan(mock.jboss_fp['url'], self.creds, self.config)
        mock.jboss_fp['body'] = orig

        assert len(matches) == 0

    @responses.activate
    def test_idrac_post(self):
        responses.add(** mock.idrac_auth)
        requests.post(mock.idrac_auth['url'],
                      {"username": "root", "password": "calvin"},
                      verify=False)

    def test_print_contributors(self):
        changeme.print_contributors(self.creds)

    def test_print_creds(self):
        changeme.print_creds(self.creds)

    @responses.activate
    def test_do_scan_fingerprint(self):
        responses.add(** mock.tomcat_fp)
        self.config['fingerprint'] = True
        match = changeme.do_scan(mock.tomcat_fp['url'], self.creds, self.config)
        self.config['fingerprint'] = False

        assert len(match) == 1
        assert match[0]['name'] == self.tomcat_name

    @responses.activate
    def test_do_scan_get(self):
        responses.add(** mock.ipcamera_fp)
        responses.add(** mock.ipcamera_auth)

        changeme.logger = changeme.setup_logging(True, True, None)
        matches = changeme.do_scan(mock.ipcamera_fp['url'], self.creds, self.config)

        assert len(matches) == 1
        #assert matches[0]['name'] == self.c_name
