import logging
from logutils import colorize
import os
import re
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import sys
import version
from changeme.scan_engine import ScanEngine

def init_logging(verbose, debug, logfile):
    """
    Logging levels:
        - Critical: Default credential found
        - Error: error in the program
        - Warning: Verbose data
        - Info: more verbose
        - Debug: Extra info for debugging purposes
    """
    global logger
    # Set up our logging object
    logger = logging.getLogger(__name__)

    if debug:
        logger.setLevel(logging.DEBUG)
    elif verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)

    if logfile:
        # Create file handler which logs even debug messages
        #######################################################################
        fh = logging.FileHandler(logfile)

        # create formatter and add it to the handler
        formatter = logging.Formatter('[%(asctime)s][%(levelname)s] %(message)s')
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    # Set up the StreamHandler so we can write to the console
    ###########################################################################
    # create console handler with a higher log level
    ch = colorize.ColorizingStreamHandler(sys.stdout)

    # set custom colorings:
    ch.level_map[logging.DEBUG] = [None, 2, False]
    ch.level_map[logging.INFO] = [None, 'white', False]
    ch.level_map[logging.WARNING] = [None, 'yellow', False]
    ch.level_map[logging.ERROR] = [None, 'red', False]
    ch.level_map[logging.CRITICAL] = [None, 'green', False]
    formatter = logging.Formatter('[%(asctime)s] %(message)s', datefmt='%H:%M:%S')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # Adjust the loggers for requests and urllib3
    logging.getLogger('requests').setLevel(logging.ERROR)
    logging.getLogger('urllib3').setLevel(logging.ERROR)
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    return logger

def banner(version):
    b = """
 #####################################################
#       _                                             #
#   ___| |__   __ _ _ __   __ _  ___ _ __ ___   ___   #
#  / __| '_ \ / _` | '_ \ / _` |/ _ \ '_ ` _ \ / _ \\  #
# | (__| | | | (_| | | | | (_| |  __/ | | | | |  __/  #
#  \___|_| |_|\__,_|_| |_|\__, |\___|_| |_| |_|\___|  #
#                         |___/                       #
#  v%s                                             #
#  Default Credential Scanner by @ztgrace             #
 #####################################################
    """ % version

    return b


class config(object):
    def __init__(self, protocol, category, name, proxy, log, verbose, debug, timeout, useragent, delay, port, ssl, custom_creds):
        self.protocol=protocol
        self.category=category
        self.name=name
        self.proxy=proxy
        self.log=log
        self.verbose=verbose
        self.debug=debug
        self.timeout=timeout
        self.useragent=useragent
        self.delay=delay
        self.port=port
        self.ssl=ssl
        self.custom_creds = custom_creds
        self.logger = init_logging(self.verbose, self.debug, self.log)


def run_changeme(protocol, category, name, targets, port, ssl, proxy, log, verbose, debug, timeout, useragent, delay, creds, custom_creds):
    config_obj = config(protocol, category, name, proxy, log, verbose, debug, timeout, useragent, delay, port, ssl, custom_creds)
    s = ScanEngine()
    return s.scan(creds, targets, config_obj)
