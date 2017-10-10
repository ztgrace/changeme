import argparse
from changeme import core
from .core import cli_args
from copy import deepcopy
import logging
import mock
import os


logger = logging.getLogger('changeme')

def reset_handlers():
    logger = logging.getLogger('changeme')
    logger.handlers = []
    core.remove_queues()

mongodb_args = deepcopy(cli_args)
mongodb_args['target'] = 'mongodb://127.0.0.1'
@mock.patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(**mongodb_args))
def test_mongodb(mock_args):
    reset_handlers()
    se = core.main()

    try:
        assert se.found_q.qsize() == 1
    except Exception as e:
        # Raise an assertion error if we're in Travis CI and fail
        if os.environ.get('TRAVIS', None):
            raise e
        # Warn if we're not Travis CI
        else:
            logger.warning('mongodb failed')

