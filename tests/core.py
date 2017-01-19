import argparse
from changeme import *
from copy import deepcopy
import mock
from nose.tools import *


cli_args = {'category': None,
            'contributors': False,
            'debug': True,
            'delay': 500,
            'dump': False,
            'dryrun': False,
            'fingerprint': False,
            'log': None,
            'name': None,
            'nmap': None,
            'proxy': None,
            'output': None,
            'subnet': None,
            'shodan_query': None,
            'shodan_key': None,
            'target': '127.0.0.1',
            'targets': None,
            'threads': 10,
            'timeout': 10,
            'useragent': None,
            'validate': False,
            'verbose': False,}



def test_banner():
    core.banner(version.__version__)


def test_debug_logger():
    logger = core.init_logging(True, True, None)


def test_verbose_logger():
    logger = core.init_logging(True, False, None)


def test_regular_logger():
    logger = core.init_logging(False, False, None)


def test_file_logger():
    logger = core.init_logging(False, False, '/tmp/test.log')


no_args = deepcopy(cli_args)
no_args['target'] = None
@raises(SystemExit)
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**no_args))
def test_no_args(mock_args):
    core.Config()


args = deepcopy(cli_args)
args['target'] = '127.0.0.1'
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**args))
def test_target(mock_args):
    core.Config()


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
    config = core.Config()
    creds = core.load_creds(config)
    core.print_contributors(creds)


args = deepcopy(cli_args)
args['dump'] = True
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**args))
def test_print_creds(mock_args):
    config = core.Config()
    creds = core.load_creds(config)
    core.print_creds(creds)
