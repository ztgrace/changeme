import argparse
from changeme.scan_engine import ScanEngine
from changeme import core
from core import cli_args
from copy import deepcopy
import csv
import logging
import mock
from mock_responses import MockResponses
from nose.tools import *
import os
import responses

"""
TODO:
 - Custom headers
 - 429 response code
 -

"""

def reset_handlers():
    logger = logging.getLogger('changeme')
    logger.handlers = []

fp_args = deepcopy(cli_args)
fp_args['nmap'] = 'tests/tomcat_nmap.xml'
@responses.activate
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**fp_args))
def test_tomcat_match_nmap(mock_args):
    responses.add(**MockResponses.tomcat_fp)

    reset_handlers()
    args = core.parse_args()
    core.init_logging(args['args'].verbose, args['args'].debug, args['args'].log)
    config = core.Config(args['args'], args['parser'])
    creds = core.load_creds(config)
    s = ScanEngine(creds, config)
    s._build_targets()
    s.fingerprint_targets(s.fingerprints, s.scanners)

    # Queue is not serializeable so we can't copy it using deepcopy
    scanners = list()
    while not s.scanners.empty():
        scanner = s.scanners.get()
        assert scanner.url == 'http://127.0.0.1:8080/manager/html' or scanner.url == 'http://127.0.0.1:8080/tomcat/manager/html'
        scanners.append(scanner)

    assert len(scanners) == 34

    for scanner in scanners:
        s.scanners.put(scanner)

    responses.reset()
    responses.add(**MockResponses.tomcat_auth)
    s._scan(s.scanners, s.found_q)
    assert s.found_q.qsize() == 17


@responses.activate
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**cli_args))
def test_tomcat_invalid_creds(mock_args):
    responses.add(**MockResponses.tomcat_fp)
    reset_handlers()
    se = core.main()
    assert se.found_q.qsize() == 0

@responses.activate
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**cli_args))
def test_jboss_scan_fail(mock_args):
    responses.add(**MockResponses.jboss_fp)
    responses.add(**MockResponses.jboss_auth_fail)

    reset_handlers()
    args = core.parse_args()
    core.init_logging(args['args'].verbose, args['args'].debug, args['args'].log)
    config = core.Config(args['args'], args['parser'])
    creds = core.load_creds(config)
    se = ScanEngine(creds, config)
    se._build_targets()
    se.fingerprint_targets(se.fingerprints, se.scanners)
    assert se.scanners.qsize() == 1

    se._scan(se.scanners, se.found_q)
    assert se.found_q.qsize() == 0


@responses.activate
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**cli_args))
def test_jboss_scan_success(mock_args):
    responses.add(**MockResponses.jboss_fp)
    responses.add(**MockResponses.jboss_auth)
    reset_handlers()
    se = core.main()
    assert se.found_q.qsize() == 1


subnet_args = deepcopy(cli_args)
subnet_args['subnet'] = '127.0.0.1/32'
subnet_args['target'] = None
@responses.activate
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**subnet_args))
def test_jboss_scan_success_subnet(mock_args):
    responses.add(**MockResponses.jboss_fp)
    responses.add(**MockResponses.jboss_auth)
    reset_handlers()
    se = core.main()
    assert se.found_q.qsize() == 1


@responses.activate
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**cli_args))
def test_jboss_csrf_fail(mock_args):
    responses.add(**MockResponses.jboss_fp_no_csrf)
    reset_handlers()
    se = core.main()
    assert se.found_q.qsize() == 0


idrac_args = deepcopy(cli_args)
idrac_args['name'] = "Dell iDRAC"
@responses.activate
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**idrac_args))
def test_idrac_scan_success(mock_args):
    responses.reset()
    responses.add(**MockResponses.idrac_fp)
    responses.add(**MockResponses.idrac_auth)
    reset_handlers()
    se = core.main()
    assert se.found_q.qsize() == 1


targets_args = deepcopy(cli_args)
targets_args['target'] = None
targets_args['targets'] = '/tmp/targets.txt'
@responses.activate
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**targets_args))
def test_targets_scan_success(mock_args):
    responses.reset()
    responses.add(**MockResponses.idrac_fp)
    responses.add(**MockResponses.idrac_auth)
    with open(targets_args['targets'], 'wb') as fout:
        fout.write('127.0.0.1' + '\n')

    reset_handlers()
    se = core.main()
    assert se.found_q.qsize() == 1


csv_args = deepcopy(cli_args)
csv_args['log'] = '/tmp/output.log'
csv_args['output'] = '/tmp/output.csv'
@responses.activate
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**csv_args))
def test_csv_output(mock_args):
    responses.add(**MockResponses.jboss_fp)
    responses.add(**MockResponses.jboss_auth)
    reset_handlers()
    se = core.main()
    assert se.found_q.qsize() == 1

    assert os.path.isfile(csv_args['output'])
    i = 0
    with open(csv_args['output'], 'rb') as csvfile:
        reader = csv.reader(csvfile)
        for line in reader:
            if i == 1:
                assert line[0] == 'JBoss AS 6'
                assert line[1] == 'admin'
                assert line[2] == 'admin'
                assert line[3] == 'http://127.0.0.1:8080/admin-console/login.seam'
            i += 1

    assert os.path.isfile(csv_args['log'])


dr_args = deepcopy(cli_args)
dr_args['dryrun'] = True
@raises(SystemExit)
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**dr_args))
def test_dryrun(mock_args):
    reset_handlers()
    se = core.main()
    assert se.found_q.qsize() == 0
