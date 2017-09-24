import argparse
from changeme import *
from copy import deepcopy
import mock
from nose.tools import *
from netaddr import IPAddress


cli_args = {'all': False,
            'category': None,
            'contributors': False,
            'debug': True,
            'delay': 500,
            'dump': False,
            'dryrun': False,
            'fingerprint': False,
            'fresh': True,
            'log': None,
            'mkcred': False,
            'name': None,
            'noversion': True,
            'output': None,
            'oa': False,
            'portoverride': False,
            'protocols': 'http',
            'proxy': None,
            'resume': False,
            'shodan_query': None,
            'shodan_key': None,
            'target': '127.0.0.1',
            'threads': 20,
            'timeout': 10,
            'useragent': None,
            'validate': False,
            'verbose': False,}



def test_banner():
    core.banner(version.__version__)

no_args = deepcopy(cli_args)
no_args['target'] = None
@raises(SystemExit)
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**no_args))
def test_no_args(mock_args):
    args = core.parse_args()
    core.init_logging(args['args'].verbose, args['args'].debug, args['args'].log)
    config = core.Config(args['args'], args['parser'])


args = deepcopy(cli_args)
args['target'] = '127.0.0.1'
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**args))
def test_target(mock_args):
    args = core.parse_args()
    core.init_logging(args['args'].verbose, args['args'].debug, args['args'].log)
    config = core.Config(args['args'], args['parser'])


"""
args = deepcopy(cli_args)
args['targets'] = '/etc/hosts'
args['target'] = None
print args
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**args))
def test_targets(mock_args):
    core.Config()
"""

args = deepcopy(cli_args)
args['contributors'] = True
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**args))
def test_contributors(mock_args):
    args = core.parse_args()
    core.init_logging(args['args'].verbose, args['args'].debug, args['args'].log)
    config = core.Config(args['args'], args['parser'])
    creds = core.load_creds(config)
    core.print_contributors(creds)


args = deepcopy(cli_args)
args['dump'] = True
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**args))
def test_print_creds(mock_args):
    args = core.parse_args()
    core.init_logging(args['args'].verbose, args['args'].debug, args['args'].log)
    config = core.Config(args['args'], args['parser'])
    creds = core.load_creds(config)
    core.print_creds(creds)
