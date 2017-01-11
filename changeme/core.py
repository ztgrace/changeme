import argparse
from cerberus import Validator
from changeme import cred
import logging
from logutils import colorize
import os
import re
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import schema
import sys
import version
import yaml


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
        formatter = logging.Formatter(
            '[%(asctime)s][%(levelname)s] %(message)s')
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
    formatter = logging.Formatter(
        '[%(asctime)s] %(message)s', datefmt='%H:%M:%S')
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


class Config(object):
    def __init__(self):
        self.logger = None
        self.parse_args()

    def _validate_args(self, ap):
        if (not self.subnet and not self.targets and not self.validate and not self.contributors and not self.dump
                and not self.shodan_query and not self.nmap and not self.target):
            ap.print_help()
            quit()

        if self.target:
            self._file_exists(self.target)

        if self.nmap:
            self._file_exists(self.nmap)

        if self.proxy and re.match('^https?://[0-9\.]+:[0-9]{1,5}$', self.proxy):
            self.proxy = {'http': self.proxy,
                     'https': self.proxy}
            logger.info('Setting proxy to %s' % self.proxy)
        elif self.proxy:
            logger.error('Invalid proxy, must be http(s)://x.x.x.x:8080')
            sys.exit()

        if self.delay and self.delay != 0:
            if isinstance(self.delay, int) and 0 <= self.delay <= 1000:
                self.logger.info('Delay is set to %d milliseconds' % self.delay)
            else:
                self.logger.error('Invalid delay type. Delay must be an integer between 0 and 1000.  Delay is: %s' %
                                    type(self.delay))

        # Drop logging level to INFO to see the fingerprint messages
        if self.fingerprint:
            self.logger.setLevel(logging.INFO)

    def parse_args(self):
        ap = argparse.ArgumentParser(description='Default credential scanner v%s' % version.__version__)
        ap.add_argument('--category', '-c', type=str, help='Category of default creds to scan for', default=None)
        ap.add_argument('--contributors', action='store_true', help='Display cred file contributors')
        ap.add_argument('--debug', '-d', action='store_true', help='Debug output')
        ap.add_argument('--dump', action='store_true', help='Print all of the loaded credentials')
        ap.add_argument('--dryrun', '-r', action='store_true', help='Print urls to be scan, but don\'t scan them')
        ap.add_argument('--fingerprint', '-f', action='store_true', help='Fingerprint targets, but don\'t check creds')
        ap.add_argument('--log', '-l', type=str, help='Write logs to logfile', default=None)
        ap.add_argument('--name', '-n', type=str, help='Narrow testing to the supplied credential name', default=None)
        ap.add_argument('--proxy', '-p', type=str, help='HTTP(S) Proxy', default=None)
        ap.add_argument('--output', '-o', type=str, help='Name of file to write CSV results', default=None)
        ap.add_argument('--subnet', '-s', type=str, help='Subnet or IP to scan')
        ap.add_argument('--shodan_query', '-q', type=str, help='Shodan query')
        ap.add_argument('--shodan_key', '-k', type=str, help='Shodan API key')
        ap.add_argument('--target', type=str, help='Specific target to scan (IP:PORT)')
        ap.add_argument('--targets', type=str, help='File of targets to scan')
        ap.add_argument('--threads', '-t', type=int, help='Number of threads, default=10', default=10)
        ap.add_argument('--timeout', type=int, help='Timeout in seconds for a request, default=10', default=10)
        ap.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
        ap.add_argument('--validate', action='store_true', help='Validate creds files')
        ap.add_argument('--nmap', '-x', type=str, help='Nmap XML file to parse')
        ap.add_argument('--useragent', '-ua', type=str, help="User agent string to use")
        ap.add_argument('--delay', '-dl', type=int, help="Specify a delay in milliseconds to avoid 429 status codes default=500", default=500)
        args = ap.parse_args()

        # Convert argparse Namespace to a dict and make the keys + values member variables of the config class
        args = vars(args)
        for key in args:
            setattr(self, key, args[key])

        self.logger = init_logging(self.verbose, self.debug, self.log)
        self._validate_args(ap)

    def _file_exists(self, f):
        if not os.path.isfile(f):
            self.logger.error("File %s not found" % f)
            sys.exit()


def load_creds(config):
    creds = list()
    total_creds = 0
    cred_names = list()
    for root, dirs, files in os.walk('creds'):
        for fname in files:
            f = os.path.join(root, fname)
            if is_yaml(f):
                parsed = parse_yaml(f)
                if parsed:
                    if parsed['name'] in cred_names:
                        config.logger.error(
                            "[load_creds] %s: duplicate name %s" % (f, parsed['name']))
                    elif validate_cred(parsed, f):

                        if in_scope(config.name, config.category, parsed):
                            total_creds += len(parsed["auth"]["credentials"])
                            creds.append(parsed)
                            cred_names.append(parsed['name'])
                            config.logger.debug('Loaded %s' % parsed['name'])

    print('Loaded %i default credential profiles' % len(creds))
    print('Loaded %i default credentials\n' % total_creds)

    return creds


def validate_cred(cred, f):
    v = Validator()
    valid = v.validate(cred, schema.changeme_schema)
    for e in v.errors:
        logger.error("[validate_cred] Validation Error: %s, %s - %s" %
                     (f, e, v.errors[e]))

    return valid


def parse_yaml(f):
    global logger
    with open(f, 'r') as fin:
        raw = fin.read()
        try:
            parsed = yaml.load(raw)
        except(yaml.parser.ParserError):
            logger.error("[parse_yaml] %s is not a valid yaml file" % f)
            return None
    return parsed


def is_yaml(f):
    isyaml = False
    try:
        isyaml = os.path.basename(f).split('.')[1] == 'yml'
    except:
        pass
    return isyaml


def in_scope(name, category, cred):
    add = True

    if name and not name.lower() in cred['name'].lower():
        add = False
    elif category and not cred['category'] == category:
        add = False

    return add


def print_contributors(creds):
    contributors = set()
    for cred in creds:
        contributors.add(cred['contributor'])

    print "Thank you to our contributors!"
    for i in contributors:
        print i
    print


def print_creds(creds):
    for cred in creds:
        print "\n%s" % cred['name']
        for i in cred['auth']['credentials']:
            print "  - %s:%s" % (i['username'], i['password'])

