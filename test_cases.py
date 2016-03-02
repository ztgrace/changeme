#!/usr/bin/env python
# nosetests --with-coverage --cover-erase --cover-package=scanner

"""
 TODO
    - more tests around scan
"""

import scanner
from nose.tools import *
import yaml
import logging
import requests
import responses
import re
import random

tomcat_yaml = 'creds/apache_tomcat.yml'
tomcat_name = 'Apache Tomcat'
jboss_name = 'JBoss AS 6'

def get_cred(name):
    creds = scanner.load_creds()
    for i in creds:
        if i['name'] == name:
            return i

"""
    is_yaml tests
"""
def test_is_yaml_true():
    assert scanner.is_yaml(tomcat_yaml) == True

def test_is_yaml_false():
    assert scanner.is_yaml("/etc/hosts") == False

"""
    parse_yaml tests
"""
def test_parse_yaml_good():
    assert scanner.parse_yaml(tomcat_yaml)

@raises(yaml.scanner.ScannerError)
def test_parse_yaml_bad():
    assert scanner.parse_yaml("/etc/hosts")

"""
    load_creds
"""
def test_load_creds_good():
    scanner.logger = scanner.setup_logging(False, False, None)
    scanner.load_creds()

"""
    validate_cred
"""    
def test_validate_cred():
    scanner.logger = scanner.setup_logging(False, False, None)
    creds = scanner.load_creds()
    
    cred = creds[random.randrange(0, len(creds))]
    while True:
        key = random.choice(cred.keys())
        if key in scanner.required_keys:
            cred.pop(key)
            break
    
    assert scanner.validate_cred(cred, "/dev/null") == False

"""
    setup_logging tests
"""
def test_setup_logging():
    logger = scanner.setup_logging(False, False, None)
    assert logger.isEnabledFor(logging.WARNING)

def test_setup_logging_verbose():
    logger = scanner.setup_logging(True, False, None)
    assert logger.isEnabledFor(logging.INFO)

def test_setup_logging_debug():
    logger = scanner.setup_logging(False, True, None)
    assert logger.isEnabledFor(logging.INFO)
    assert logger.isEnabledFor(logging.DEBUG)

def test_setup_logging_file():
    fh = False
    logger = scanner.setup_logging(False, False, "/tmp/foo.log")
    for i in logger.handlers:
        if isinstance(i, logging.FileHandler):
            fh = True
    assert fh

"""
    get_fingerprint_matches
"""
@responses.activate
def test_get_fingerprint_matches_tomcat():
    responses.add(**{
        'method': responses.GET,
        'url': 'http://127.0.0.1:8080/manager/html', 
        'status': 401,
        'adding_headers': { 'Server': 'Apache-Coyote/1.1', 
                            'WWW-Authenticate':'Basic realm="Tomcat Manager Application'}
        })
    res = requests.get('http://127.0.0.1:8080/manager/html')

    # Verify the response came back correctly
    assert res.status_code == 401
    assert res.headers.get('WWW-Authenticate')

    creds = scanner.load_creds()
    scanner.logger = scanner.setup_logging(False, False, None)
    matches = scanner.get_fingerprint_matches(res, creds)

    matched = False
    for i in matches:
        if i['name'] == tomcat_name:
            matched = True
    assert matched


@responses.activate
def test_get_fingerprint_matches_jboss():
    responses.add(**{
        'method': responses.GET,
        'url': 'http://127.0.0.1:8080/admin-console/login.seam', 
        'status': 200,
        'body': '<p>Welcome to the JBoss AS 6 Admin Console.</p>',
        'adding_headers': { 'Server': 'Apache-Coyote/1.1'} 
        })
    res = requests.get('http://127.0.0.1:8080/admin-console/login.seam')

    # Verify the response came back correctly
    assert res.status_code == 200
    assert "Welcome to the JBoss AS 6 Admin Console" in res.text

    creds = scanner.load_creds()
    scanner.logger = scanner.setup_logging(False, False, None)
    matches = scanner.get_fingerprint_matches(res, creds)

    matched = False
    for i in matches:
        if i['name'] == jboss_name:
            matched = True
    assert matched

"""
    check_basic_auth
"""
@responses.activate
def test_check_basic_auth_tomcat():
    responses.add(**{
        'method': responses.GET,
        'url': 'http://127.0.0.1:8080/manager/html', 
        'status': 200,
        'body': '<font size="+2">Tomcat Web Application Manager</font>',
        'adding_headers': { 'Server': 'Apache-Coyote/1.1'}
        })

    scanner.logger = scanner.setup_logging(False, False, None)
    creds = scanner.load_creds()
    cred = None
    for i in creds:
        if i['name'] == tomcat_name:
            cred = i

    assert cred['name'] == tomcat_name

    matches = scanner.check_basic_auth("http://127.0.0.1:8080/manager/html", cred, False, False, None)
    assert len(matches) > 0

@responses.activate
def test_check_basic_auth_tomcat_fail():
    responses.add(**{
        'method': responses.GET,
        'url': 'http://127.0.0.1:8080/manager/html', 
        'status': 401,
        'adding_headers': { 'Server': 'Apache-Coyote/1.1', 
                            'WWW-Authenticate':'Basic realm="Tomcat Manager Application'}
        })

    cred = get_cred(tomcat_name)
    assert cred['name'] == tomcat_name

    scanner.logger = scanner.setup_logging(False, False, None)
    matches = scanner.check_basic_auth("http://127.0.0.1:8080/manager/html", cred, False, False)
    assert len(matches) == 0

"""
    check_form
"""
@responses.activate
def test_check_form_jboss():
    responses.add(**{
        'method': responses.POST,
        'url': 'http://127.0.0.1:8080/admin-console/login.seam', 
        'status': 200,
        'body': '<a>Logout</a>',
        'adding_headers': { 'Server': 'Apache-Coyote/1.1'} 
        })

    cred = get_cred(jboss_name)
    assert cred['name'] == jboss_name
    
    matches = scanner.check_form('http://127.0.0.1:8080/admin-console/login.seam', cred, {'JSESSIONID':'foobar'}, 'foobar')
    assert len(matches) > 0

@responses.activate
def test_check_form_zabbix():
    responses.add(**{
        'method': responses.POST,
        'url': 'http://127.0.0.1/zabbix/index.php', 
        'status': 200,
        'body': '<a>Logout</a>',
        })

    cred = get_cred('Zabbix')
    assert cred['name'] == 'Zabbix'
    
    matches = scanner.check_form('http://127.0.0.1/zabbix/index.php', cred, False, False)
    assert len(matches) > 0

@responses.activate
def test_check_form_zabbix_fail():
    responses.add(**{
        'method': responses.POST,
        'url': 'http://127.0.0.1/zabbix/index.php', 
        'status': 200,
        'body': 'Fail',
        })

    cred = get_cred('Zabbix')
    assert cred['name'] == 'Zabbix'
    
    matches = scanner.check_form('http://127.0.0.1/zabbix/index.php', cred, False, False)
    assert len(matches) == 0

"""
    get_csrf_token
"""
@responses.activate
def test_get_csrf_token():
    responses.add(**{
        'method': responses.GET,
        'url': 'http://127.0.0.1:8080/admin-console/login.seam', 
        'status': 200,
        'body': '<input name="javax.faces.ViewState" value="foobar" />',
        'adding_headers': { 'Server': 'Apache-Coyote/1.1'} 
        })
    res = requests.get('http://127.0.0.1:8080/admin-console/login.seam')

    cred = get_cred(jboss_name)
    assert cred['name'] == jboss_name

    csrf = scanner.get_csrf_token(res, cred)
    assert csrf == 'foobar'

@responses.activate
def test_get_csrf_token_fail():
    responses.add(**{
        'method': responses.GET,
        'url': 'http://127.0.0.1:8080/admin-console/login.seam', 
        'status': 200,
        'body': 'fail',
        'adding_headers': { 'Server': 'Apache-Coyote/1.1'} 
        })
    res = requests.get('http://127.0.0.1:8080/admin-console/login.seam')

    cred = get_cred(jboss_name)
    assert cred['name'] == jboss_name

    csrf = scanner.get_csrf_token(res, cred)
    assert csrf == False

@responses.activate
def test_get_csrf_token_no_token():
    responses.add(**{
        'method': responses.GET,
        'url': 'http://127.0.0.1/zabbix/index.php', 
        'status': 200,
        'body': 'foobar',
        })
    res = requests.get('http://127.0.0.1/zabbix/index.php')

    cred = get_cred('Zabbix')
    assert cred['name'] == 'Zabbix'

    csrf = scanner.get_csrf_token(res, cred)
    assert csrf == False

"""
    get_session_id
"""
@responses.activate
def test_get_session_id():
    responses.add(**{
        'method': responses.GET,
        'url': 'http://127.0.0.1:8080/admin-console/login.seam', 
        'status': 200,
        'body': '<p>Welcome to the JBoss AS 6 Admin Console.</p>',
        'adding_headers': { 'Set-Cookie': 'JSESSIONID=foobar'} 
        })
    res = requests.get('http://127.0.0.1:8080/admin-console/login.seam')

    cred = get_cred(jboss_name)
    assert cred['name'] == jboss_name

    sessionid = scanner.get_session_id(res, cred)
    assert sessionid['JSESSIONID'] == 'foobar'

@responses.activate
def test_get_session_id_fail():
    responses.add(**{
        'method': responses.GET,
        'url': 'http://127.0.0.1:8080/admin-console/login.seam', 
        'status': 200,
        'body': '<p>Welcome to the JBoss AS 6 Admin Console.</p>',
        'adding_headers': { 'Set-Cookie': 'foo=bar'} 
        })
    res = requests.get('http://127.0.0.1:8080/admin-console/login.seam')

    cred = get_cred(jboss_name)
    assert cred['name'] == jboss_name

    sessionid = scanner.get_session_id(res, cred)
    assert sessionid == False

@responses.activate
def test_get_session_id_no_id():
    responses.add(**{
        'method': responses.GET,
        'url': 'http://127.0.0.1:8080/manager/html',
        'status': 401,
        })
    res = requests.get('http://127.0.0.1:8080/manager/html')

    cred = get_cred(tomcat_name)
    assert cred['name'] == tomcat_name

    sessionid = scanner.get_session_id(res, cred)
    assert sessionid == False

@responses.activate
def test_scan():
    responses.add(**{
        'method': responses.GET,
        'url': 'http://127.0.0.1:8080/manager/html', 
        'status': 401,
        'adding_headers': { 'Server': 'Apache-Coyote/1.1', 
                            'WWW-Authenticate':'Basic realm="Tomcat Manager Application'}
        })
    responses.add(**{
        'method': responses.GET,
        'url': 'http://127.0.0.1:8080/admin-console/login.seam', 
        'status': 200,
        'body': '<p>Welcome to the JBoss AS 6 Admin Console.</p><input name="javax.faces.ViewState" value="foobar" />',
        'adding_headers': { 'Server': 'Apache-Coyote/1.1', 'Set-Cookie': 'JSESSIONID=foobar'}
        })

    urls = list()
    urls.append("http://127.0.0.1:8080/manager/html")
    urls.append("http://127.0.0.1:8080/admin-console/login.seam")
    urls.append("http://192.168.0.99:9999/foobar/index.php")

    threads = 1
    timeout = 5
    creds = scanner.load_creds()

    scanner.scan(urls, creds, threads, timeout, None)

@raises(SystemExit)
def test_dry_run():
    urls = list()
    urls.append("http://127.0.0.1:8080/manager/html")
    urls.append("http://127.0.0.1:8080/admin-console/login.seam")
    scanner.dry_run(urls)



def test_build_target_list():
    scanner.targets = ["127.0.0.1"]
    creds = scanner.load_creds()
    urls = scanner.build_target_list(scanner.targets, creds, None, None)
    assert(isinstance(urls, list))

    urls = scanner.build_target_list(scanner.targets, creds, tomcat_name, None)
    apache_cred = get_cred(tomcat_name)
    paths = apache_cred['path']
    
    match = True
    for url in urls:
        path = re.search("https?://[a-zA-Z0-9\.]+:?[0-9]{0,5}(.*)$", url).group(1)
        if not path in paths:
            assert False
            return

    assert True

@responses.activate
def test_do_scan():
    responses.add(**{
        'method': responses.GET,
        'url': 'http://127.0.0.1:8080/manager/html', 
        'status': 401,
        'adding_headers': { 'Server': 'Apache-Coyote/1.1', 
                            'WWW-Authenticate':'Basic realm="Tomcat Manager Application'}
        })
    responses.add(**{
        'method': responses.GET,
        'url': 'http://127.0.0.1:8080/admin-console/login.seam', 
        'status': 200,
        'body': '<p>Welcome to the JBoss AS 6 Admin Console.</p><input name="javax.faces.ViewState" value="foobar" />',
        'adding_headers': { 'Server': 'Apache-Coyote/1.1', 'Set-Cookie': 'JSESSIONID=foobar'}
        })
    scanner.creds = scanner.load_creds()
    scanner.setup_logging(True, True, None)
    scanner.do_scan("http://127.0.0.1/manager/html", scanner.creds, 10, None)
    


