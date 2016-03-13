#!/usr/bin/env python

import argparse
import requests
from requests.auth import HTTPBasicAuth
import yaml
import os
import sys
import re
from netaddr import *
from lxml import html
import threading
import logging
from logutils import colorize
from time import time
from urlparse import urlparse
from cerberus import Validator
from schema import schema

__version__ = 0.1

requests.packages.urllib3.disable_warnings()

logger = None
banner = """
  #####################################################
 #       _                                             #
 #   ___| |__   __ _ _ __   __ _  ___ _ __ ___   ___   #
 #  / __| '_ \ / _` | '_ \ / _` |/ _ \ '_ ` _ \ / _ \\  #
 # | (__| | | | (_| | | | | (_| |  __/ | | | | |  __/  #
 #  \___|_| |_|\__,_|_| |_|\__, |\___|_| |_| |_|\___|  #
 #                         |___/                       #
 #  v%s                                               #
 #  Default Credential Scanner                         #
  #####################################################
""" % __version__


def setup_logging(verbose, debug, logfile):
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

    return logger


def parse_yaml(f):
    global logger
    with open(f, 'r') as fin:
        raw = fin.read()
        try:
            parsed = yaml.load(raw)
        except(yaml.parser.ParserError):
            logger.error("%s is not a valid yaml file" % f)
            return None
    return parsed


def is_yaml(f):
    isyaml = False
    try:
        isyaml = os.path.basename(f).split('.')[1] == 'yml'
    except:
        pass
    return isyaml


def load_creds():
    creds = list()
    total_creds = 0
    cred_names = list()
    for root, dirs, files in os.walk('creds'):
        for name in files:
            f = os.path.join(root, name)
            if is_yaml(f):
                parsed = parse_yaml(f)
                if parsed:
                    if parsed['name'] in cred_names:
                        logger.error("%s: duplicate name %s" % (f, parsed['name']))
                    elif validate_cred(parsed, f):
                        total_creds += len(parsed["auth"]["credentials"])
                        creds.append(parsed)
                        cred_names.append(parsed['name'])

    print('Loaded %i default credential profiles' % len(creds))
    print('Loaded %i default credentials\n' % total_creds)

    return creds


def validate_cred(cred, f):
    v = Validator()
    valid = v.validate(cred, schema)
    for e in v.errors:
        logger.error("Validation Error: %s, %s - %s" % (f, e, v.errors[e]))

    return valid

def get_fingerprint_matches(res, creds):
    matches = list()
    for cred in creds:
        match = False
        for f in cred['fingerprint']:
            http_status = cred['fingerprint'].get('status', False)
            logger.debug('\b[get_fingerprint_matches] fingerprint status: %i, res status: %i' % (http_status, res.status_code))
            if http_status and http_status == res.status_code:
                match = True

            basic_auth_realm = cred['fingerprint'].get('basic_auth_realm', False)
            if basic_auth_realm and basic_auth_realm in res.headers.get('WWW-Authenticate', list()):
                match = True

            body_text = cred['fingerprint'].get('body', False)
            if body_text and body_text in res.text:
                match = True
                logger.debug('matched body: %s' % body_text)
            elif body_text:
                match = False

        if match:
            matches.append(cred)

    return matches


def check_basic_auth(req, candidate, sessionid=False, csrf=False, proxy=None):
    matches = list()
    for cred in candidate['auth']['credentials']:
        username = cred.get('username', "")
        password = cred.get('password', "")

        if password is None:
            password = ""

        res = requests.get(req, auth=HTTPBasicAuth(username, password), verify=False, proxies=proxy)
        if check_success(req, res, candidate, username, password):
            matches.append(cred)

    return matches


def check_form(req, candidate, sessionid=False, csrf=False, proxy=None):
    matches = list()
    data = dict()

    form = candidate['auth']['form']
    user_field = form['username']
    pass_field = form['password']
    parsed = urlparse(req)
    url = "%s://%s" % (parsed[0], parsed[1])
    urls = candidate['auth']['url']

    for k in form.keys():
        if k not in('username', 'password', 'url'):
            data[k] = form[k]

    if csrf:
        csrf_field = candidate['auth']['csrf']
        data[csrf_field] = csrf

    for cred in candidate['auth']['credentials']:
        username = cred['username']
        password = cred['password']

        data[user_field] = username
        data[pass_field] = password

        res = None
        for u in urls:
            url += u
            logger.debug("check_form form url: %s" % url)
            logger.debug('check_form post data: %s' % data)

            try:
                if sessionid:
                    res = requests.post(url, data, cookies=sessionid, verify=False, proxies=proxy)
                else:
                    res = requests.post(url, data, verify=False, proxies=proxy)
            except Exception as e:
                logger.error("Failed to connect to %s" % url)
                logger.debug(e)
                return None

            logger.debug('check_form res.status_code: %i' % res.status_code)
            logger.debug('check_form res.text: %s' % res.text)

            if res and check_success(req, res, candidate, username, password):
                matches.append(cred)

    return matches


def check_success(req, res, candidate, username, password):
        match = True
        success = candidate['auth']['success']

        if success['status'] and not success['status'] == res.status_code:
            match = False

        if match and success['body'] and success['body'] not in res.text:
            match = False

        if match:
            logger.critical('[+] Found %s default cred %s:%s at %s' % (candidate['name'], username, password, req))
            return True
        else:
            logger.info('Invalid %s default cred %s:%s' % (candidate['name'], username, password))
            return False


def get_csrf_token(res, cred):
    name = cred['auth'].get('csrf', False)
    if name:
        tree = html.fromstring(res.content)
        try:
            csrf = tree.xpath('//input[@name="%s"]/@value' % name)[0]
        except:
            logger.error("Failed to get CSRF token %s in %s" % (name, res.url))
            return False
        logger.debug('Got CSRF token %s: %s' % (name, csrf))
    else:
        csrf = False

    return csrf


def get_session_id(res, cred):
    cookie = cred['auth'].get('sessionid', False)
    if cookie:
        try:
            value = res.cookies[cookie]
        except:
            logger.error("Failed to get %s cookie from %s" % (cookie, res.url))
            return False
        return {cookie: value}
    else:
        return False


def scan(urls, creds, threads, timeout, proxy):

    Thread = threading.Thread
    for req in urls:
        while 1:
            if threading.activeCount() <= threads:
                t = Thread(target=do_scan, args=(req, creds, timeout, proxy))
                t.start()
                break


def do_scan(req, creds, timeout, proxy):
        try:
            res = requests.get(req, timeout=timeout, verify=False, proxies=proxy)
            logger.debug('[do_scan] %s - %i' % (req, res.status_code))
        except:
            logger.debug('[do_scan] Failed to connect to %s' % req)
            return

        matches = get_fingerprint_matches(res, creds)
        logger.debug("[do_scan] Found %i fingerprint matches for %s response" % (len(matches), req))
        for match in matches:
            logger.info('[do_scan] %s matched %s' % (req, match['name']))
            check = globals()['check_' + match['auth']['type']]
            csrf = get_csrf_token(res, match)
            sessionid = get_session_id(res, match)
            check(req, match, sessionid, csrf, proxy)


def dry_run(urls):
    logger.info("Dry run URLs:")
    for url in urls:
        print url
    sys.exit()


def build_target_list(targets, creds, name, category):

    # Build target list
    urls = list()
    for target in targets:
        for c in creds:
            if name and not name == c['name']:
                continue
            if category and not category == c['category']:
                continue

            port = c.get('default_port', 80)
            ssl = c.get('ssl', False)
            if ssl:
                proto = 'https'
            else:
                proto = 'http'

            paths = c.get('fingerprint')["url"]

            for path in paths:
                url = '%s://%s:%s%s' % (proto, target, port, path)
                urls.append(url)
                logger.debug('Rendered url: %s' % url)

    return urls


def main():
    print banner
    targets = list()
    proxy = None
    global logger

    start = time()

    ap = argparse.ArgumentParser(description='Default credential scanner v%s' % (__version__))
    ap.add_argument('--category', '-c', type=str, help='Category of default creds to scan for', default=None)
    ap.add_argument('--debug', '-d', action='store_true', help='Debug output')
    ap.add_argument('--dryrun', '-r', action='store_true', help='Print urls to be scan, but don\'t scan them')
    ap.add_argument('--log', '-l', type=str, help='Write logs to logfile', default=None)
    ap.add_argument('--name', '-n', type=str, help='Narrow testing to the supplied credential name', default=None)
    ap.add_argument('--proxy', '-p', type=str, help='HTTP(S) Proxy', default=None)
    ap.add_argument('--subnet', '-s', type=str, help='Subnet or IP to scan')
    ap.add_argument('--targets', type=str, help='File of targets to scan')
    ap.add_argument('--threads', '-t', type=int, help='Number of threads', default=10)
    ap.add_argument('--timeout', type=int, help='Timeout in seconds for a request', default=10)
    ap.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    ap.add_argument('--validate', action='store_true', help='Validate creds files')
    args = ap.parse_args()

    setup_logging(args.verbose, args.debug, args.log)

    if not args.subnet and not args.targets and not args.validate:
        logger.error('Need to supply a subnet or targets file.')
        ap.print_help()
        sys.exit()

    if args.subnet:
        for ip in IPNetwork(args.subnet).iter_hosts():
            targets.append(ip)

    if args.targets:
        with open(args.targets, 'r') as fin:
            targets = [x.strip('\n') for x in fin.readlines()]

    logger.info("Loaded %i targets" % len(targets))

    if args.proxy and re.match('^https?://[0-9\.]+:[0-9]{1,5}$', args.proxy):
        proxy = {'http': args.proxy,
                 'https': args.proxy}
        logger.info('Setting proxy to %s' % args.proxy)
    elif args.proxy:
        logger.error('Invalid proxy')
        sys.exit()

    if args.validate:
        load_creds()
        sys.exit()

    creds = load_creds()
    urls = build_target_list(targets, creds, args.name, args.category)

    if args.dryrun:
        dry_run(urls)

    logger.info('Scanning %i URLs' % len(urls))

    scan(urls, creds, args.threads, args.timeout, proxy)


if __name__ == '__main__':
    main()
