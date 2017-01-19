import argparse
from core import cli_args
from changeme.scan_engine import ScanEngine
from changeme import core
from copy import deepcopy
import mock
from mock_responses import MockResponses
import requests
import responses

fp_args = deepcopy(cli_args)
fp_args['fingerprint'] = True
fp_args['nmap'] = 'tests/tomcat_nmap.xml'
@responses.activate
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**fp_args))
def test_tomcat_fp_match_nmap(mock_args):
    responses.add(**MockResponses.tomcat_fp)

    config = core.Config()
    creds = core.load_creds(config)
    s = ScanEngine(creds, config)
    s._build_targets()
    s.fingerprint_targets()

    assert len(s.scanners) == 34
    for x in s.scanners:
        assert x.url == 'http://127.0.0.1:8080/manager/html' or x.url == 'http://127.0.0.1:8080/tomcat/manager/html'


"""
TODO: get responses working with callback to handle two responses based on authenticate header being in place

@responses.activate
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**cli_args))
def test_tomcat_scan(mock_args):
    def tc_callback(req):
        #if 'Authorization' in req.headers:
        #    res = 200, {'Server': 'Apache-Coyote/1.1'}, '<font size="+2">Tomcat Web Application Manager</font>'
        #    return res
        #raise requests.RequestException('Requests exception XX')
        return 401, {'WWW-Authenticate': 'Basic realm="Tomcat Manager Application', 'Server': 'Apache-Coyote/1.1'}, ''

    responses.add(**MockResponses.tomcat_fp)
    responses.add_callback(responses.GET,
                           'http://127.0.0.1:8080/tomcat/manager/html',
                           callback=tc_callback)

    config = core.Config()
    creds = core.load_creds(config)
    s = ScanEngine(creds, config)
    s.scan()
"""


@responses.activate
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**cli_args))
def test_jboss_scan_fail(mock_args):
    responses.add(**MockResponses.jboss_fp)
    responses.add(**MockResponses.jboss_auth_fail)

    config = core.Config()
    creds = core.load_creds(config)
    s = ScanEngine(creds, config)
    s.scan()


@responses.activate
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**cli_args))
def test_jboss_scan_success(mock_args):
    responses.reset()
    responses.add(**MockResponses.jboss_fp)
    responses.add(**MockResponses.jboss_auth)

    config = core.Config()
    creds = core.load_creds(config)
    s = ScanEngine(creds, config)
    s.scan()


@responses.activate
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**cli_args))
def test_jboss_csrf_fail(mock_args):
    csrf_fail = deepcopy(MockResponses.jboss_fp)
    csrf_fail['body'] = 'fail'
    responses.add(**csrf_fail)

    config = core.Config()
    creds = core.load_creds(config)
    s = ScanEngine(creds, config)
    s.scan()


idrac_args = deepcopy(cli_args)
idrac_args['name'] = "Dell iDRAC"
@responses.activate
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**idrac_args))
def test_idrac_scan_success(mock_args):
    responses.reset()
    responses.add(**MockResponses.idrac_fp)
    responses.add(**MockResponses.idrac_auth)

    config = core.Config()
    creds = core.load_creds(config)
    s = ScanEngine(creds, config)
    s.scan()
