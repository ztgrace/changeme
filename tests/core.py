import argparse
from changeme import *
import mock

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


@mock.patch('argparse.ArgumentParser.parse_args',
            return_value=argparse.Namespace(category=None, contributors=False, debug=False))
def test_config_base(**kwargs):
    config = core.config()
