import argparse
from changeme.scan_engine import ScanEngine
from changeme.target import Target
from changeme import core
from core import cli_args
from copy import deepcopy
import csv
import json
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
fp_args['name'] = 'Tomcat'
@responses.activate
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**fp_args))
def test_tomcat_match_nmap(mock_args):
    def tomcat_callback(request):
        if request.headers.get('Authorization', False):
            return (200, MockResponses.tomcat_auth['adding_headers'], MockResponses.tomcat_auth['body'])
        else:
            return (401, MockResponses.tomcat_fp['adding_headers'], '')

    responses.add_callback(
        responses.GET,
        MockResponses.tomcat_fp['url'],
        callback=tomcat_callback,
    )

    reset_handlers()
    try:
        os.remove(core.PERSISTENT_QUEUE)
    except OSError:
        pass

    args = core.parse_args()
    core.init_logging(args['args'].verbose, args['args'].debug, args['args'].log)
    config = core.Config(args['args'], args['parser'])
    creds = core.load_creds(config)
    s = ScanEngine(creds, config)
    s._build_targets()
    print "fp: %i" % s.fingerprints.qsize()
    s.fingerprint_targets(s.fingerprints, s.scanners)

    # Queue is not serializeable so we can't copy it using deepcopy
    scanners = list()
    print "scanners: %s" % s.scanners.qsize()
    #assert s.scanners.qsize() == 68

    t1 = Target(host='127.0.0.1', port=8080, protocol='http', url='/manager/html')
    t2 = Target(host='127.0.0.1', port=8080, protocol='http', url='/tomcat/manager/html')
    while s.scanners.qsize() > 0:
        scanner = s.scanners.get()
        assert scanner.url == t1 or scanner.url == t2
        scanners.append(scanner)

    # Load the scanners back into the queue
    for scanner in scanners:
        s.scanners.put(scanner)
    assert s.scanners.qsize() == 34

    responses.reset()
    responses.add(**MockResponses.tomcat_auth)
    s._scan(s.scanners, s.found_q)
    print s.found_q.qsize()
    assert s.found_q.qsize() == 17


fp_args = deepcopy(cli_args)
fp_args['fingerprint'] = True
fp_args['name'] = 'Tomcat'
@responses.activate
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**fp_args))
def test_tomcat_fingerprint(mock_args):
    responses.add(**MockResponses.tomcat_fp)
    reset_handlers()
    se = core.main()
    print("Scanners:",se.scanners.qsize())
    assert se.scanners.qsize() == 34
    os.remove(core.PERSISTENT_QUEUE)

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
subnet_args['target'] = '127.0.0.1/32'
subnet_args['protocols'] = 'http'
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
targets_args['target'] = '/tmp/targets.txt'
@responses.activate
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**targets_args))
def test_targets_scan_success(mock_args):
    responses.reset()
    responses.add(**MockResponses.idrac_fp)
    responses.add(**MockResponses.idrac_auth)
    with open(targets_args['target'], 'w') as fout:
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
    with open(csv_args['output'], 'r') as csvfile:
        reader = csv.reader(csvfile)
        for line in reader:
            if i == 1:
                assert line[0] == 'JBoss AS 6'
                assert line[1] == 'admin'
                assert line[2] == 'admin'
                assert line[3] == 'http://127.0.0.1:8080/admin-console/login.seam'
            i += 1

    assert os.path.isfile(csv_args['log'])


json_args = deepcopy(cli_args)
json_args['output'] = '/tmp/output.json'
json_args['json'] = True
@responses.activate
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**json_args))
def test_json_output(mock_args):
    responses.add(**MockResponses.jboss_fp)
    responses.add(**MockResponses.jboss_auth)
    reset_handlers()
    se = core.main()
    assert se.found_q.qsize() == 1

    assert os.path.isfile(json_args['output'])
    i = 0
    with open(json_args['output'], 'r') as json_file:
        j = json.loads(json_file.read())
        assert j["results"][0]['name']      == 'JBoss AS 6'
        assert j['results'][0]['username']  == 'admin'
        assert j['results'][0]['password']  == 'admin'
        assert j['results'][0]['target']    == 'http://127.0.0.1:8080/admin-console/login.seam'


dr_args = deepcopy(cli_args)
dr_args['dryrun'] = True
@raises(SystemExit)
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**dr_args))
def test_dryrun(mock_args):
    reset_handlers()
    se = core.main()
    assert se.found_q.qsize() == 0


es_args = deepcopy(cli_args)
es_args['name'] = "elasticsearch"
@responses.activate
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**es_args))
def test_es_scan_success(mock_args):
    responses.reset()
    responses.add(**MockResponses.elasticsearch)
    reset_handlers()
    se = core.main()
    assert se.found_q.qsize() == 1
