import argparse
from changeme import core
from .core import cli_args
from copy import deepcopy
import logging
import mock



def reset_handlers():
    logger = logging.getLogger('changeme')
    logger.handlers = []
    core.remove_queues()

snmp_args = deepcopy(cli_args)
snmp_args['protocols'] = 'snmp'
snmp_args['name'] = 'publicprivate'
snmp_args['target'] = 'demo.snmplabs.com'
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**snmp_args))
def test_snmp(mock_args):
    reset_handlers()
    se = core.main()
    assert se.found_q.qsize() == 2


snmp_args = deepcopy(cli_args)
snmp_args['name'] = 'publicprivate'
snmp_args['target'] = 'snmp://demo.snmplabs.com'
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**snmp_args))
def test_snmp_proto(mock_args):
    reset_handlers()
    se = core.main()
    assert se.found_q.qsize() == 2
    
