import argparse
from cerberus import Validator
from changeme import cred
import logging
import os
import random
import re
import schema
import sys
import version
import yaml


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
        self.parse_args()

    def _validate_args(self, ap):
        logger = logging.getLogger('changeme')
        if (not self.subnet and not self.targets and not self.validate and not self.contributors and not self.dump
                and not self.shodan_query and not self.nmap and not self.target):
            ap.print_help()
            quit()

        if self.targets:
            self._file_exists(self.target)

        if self.nmap:
            self._file_exists(self.nmap)

        if self.proxy and re.match('^https?://[0-9\.]+:[0-9]{1,5}$', self.proxy):
            self.proxy = {'http': self.proxy, 'https': self.proxy}
            logger.info('Setting proxy to %s' % self.proxy)
        elif self.proxy:
            logger.error('Invalid proxy, must be http(s)://x.x.x.x:8080')
            sys.exit()

        if self.delay and self.delay != 0:
            if isinstance(self.delay, int) and 0 <= self.delay <= 1000:
                logger.debug('Delay is set to %d milliseconds' % self.delay)
            else:
                logger.error('Invalid delay type. Delay must be an integer between 0 and 1000.  Delay is: %s' %
                                    type(self.delay))

        if self.verbose:
            logger.setLevel(logging.INFO)
        if self.debug:
            logger.setLevel(logging.DEBUG)

        # Drop logging level to INFO to see the fingerprint messages
        if self.fingerprint:
            logger.setLevel(logging.INFO)

        self.useragent = {'User-Agent': self.useragent if self.useragent else get_useragent()}

    def parse_args(self):
        ap = argparse.ArgumentParser(description='Default credential scanner v%s' % version.__version__)
        ap.add_argument('--category', '-c', type=str, help='Category of default creds to scan for', default=None)
        ap.add_argument('--contributors', action='store_true', help='Display cred file contributors')
        ap.add_argument('--debug', '-d', action='store_true', help='Debug output')
        ap.add_argument('--delay', '-dl', type=int, help="Specify a delay in milliseconds to avoid 429 status codes default=500", default=500)
        ap.add_argument('--dump', action='store_true', help='Print all of the loaded credentials')
        ap.add_argument('--dryrun', '-r', action='store_true', help='Print urls to be scan, but don\'t scan them')
        ap.add_argument('--fingerprint', '-f', action='store_true', help='Fingerprint targets, but don\'t check creds')
        ap.add_argument('--log', '-l', type=str, help='Write logs to logfile', default=None)
        ap.add_argument('--name', '-n', type=str, help='Narrow testing to the supplied credential name', default=None)
        ap.add_argument('--nmap', '-x', type=str, help='Nmap XML file to parse', default=None)
        ap.add_argument('--proxy', '-p', type=str, help='HTTP(S) Proxy', default=None)
        ap.add_argument('--output', '-o', type=str, help='Name of file to write CSV results', default=None)
        ap.add_argument('--subnet', '-s', type=str, help='Subnet or IP to scan', default=None)
        ap.add_argument('--shodan_query', '-q', type=str, help='Shodan query', default=None)
        ap.add_argument('--shodan_key', '-k', type=str, help='Shodan API key', default=None)
        ap.add_argument('--target', type=str, help='Specific target to scan (IP:PORT)', default=None)
        ap.add_argument('--targets', type=str, help='File of targets to scan', default=None)
        ap.add_argument('--threads', '-t', type=int, help='Number of threads, default=10', default=10)
        ap.add_argument('--timeout', type=int, help='Timeout in seconds for a request, default=10', default=10)
        ap.add_argument('--useragent', '-ua', type=str, help="User agent string to use", default=None)
        ap.add_argument('--validate', action='store_true', help='Validate creds files', default=False)
        ap.add_argument('--verbose', '-v', action='store_true', help='Verbose output', default=False)
        args = ap.parse_args()

        # Convert argparse Namespace to a dict and make the keys + values member variables of the config class
        args = vars(args)
        for key in args:
            setattr(self, key, args[key])

        self._validate_args(ap)

    def _file_exists(self, f):
        if not os.path.isfile(f):
            self.logger.error("File %s not found" % f)
            sys.exit()


def load_creds(config):
    logger = logging.getLogger('changeme')
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
                        logger.error("[load_creds] %s: duplicate name %s" % (f, parsed['name']))
                    elif validate_cred(parsed, f):

                        if in_scope(config.name, config.category, parsed):
                            total_creds += len(parsed["auth"]["credentials"])
                            creds.append(parsed)
                            cred_names.append(parsed['name'])
                            logger.debug('Loaded %s' % parsed['name'])

    print('Loaded %i default credential profiles' % len(creds))
    print('Loaded %i default credentials\n' % total_creds)

    return creds


def validate_cred(cred, f):
    v = Validator()
    valid = v.validate(cred, schema.changeme_schema)
    for e in v.errors:
        logging.getLogger('changeme').error("[validate_cred] Validation Error: %s, %s - %s" %
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

def get_useragent():
    headers_useragents = [
        'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
        'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
        'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
        'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
        'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
        'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
        'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
        'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
        'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
        'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
        'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51'
    ]
    return random.choice(headers_useragents)
