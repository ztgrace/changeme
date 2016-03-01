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

__version__ = 0.1

requests.packages.urllib3.disable_warnings()

logger = None
banner = """
################################################################################
#                                                                              #
# Default Credential Scanner v%s                                              #
#                                                                              #
################################################################################
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
        ################################################################################
        fh = logging.FileHandler(logfile)

        # create formatter and add it to the handler
        formatter = logging.Formatter('[%(asctime)s][%(levelname)s] %(message)s')
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    # Set up the StreamHandler so we can write to the console
    ################################################################################
    # create console handler with a higher log level
    ch = colorize.ColorizingStreamHandler(sys.stdout)

    # set custom colorings:
    ch.level_map[logging.DEBUG] = [None, 2, False]
    ch.level_map[logging.INFO] = [None, 'white', False]
    ch.level_map[logging.WARNING] = [None, 'yellow', False]
    ch.level_map[logging.ERROR] = [None, 'red', False]
    ch.level_map[logging.CRITICAL] = [None, 'green', False]
    formatter = logging.Formatter('[%(asctime)s] %(message)s', datefmt='%H:%M:%S')
    #formatter = logging.Formatter('[%(asctime)s][%(levelname)s] %(message)s', datefmt='%H:%M:%S')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # Adjust the loggers for requests and urllib3
    logging.getLogger('requests').setLevel(logging.ERROR)
    logging.getLogger('urllib3').setLevel(logging.ERROR)

    return logger


def parse_yaml(f):
    with open(f, 'r') as fin:
        raw = fin.read()
        parsed = yaml.load(raw)
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
    for root, dirs, files in os.walk('creds'):
        for name in files:
            f = os.path.join(root, name)
            if is_yaml(f):
                parsed = parse_yaml(f)
                total_creds += len(parsed["credentials"])
                creds.append(parsed)

    print('Loaded %i default credential profiles' % len(creds))
    print('Loaded %i default credentials\n' % total_creds)

    return creds

def get_fingerprint_matches(res, creds):
    matches = list()
    for cred in creds:
        match = False
        for f in cred['fingerprint']:
            http_status = f.get('http_status', False)
            logger.debug('\b[get_fingerprint_matches] fingerprint status: %i, res status: %i' % (http_status, res.status_code))
            if http_status and http_status == res.status_code:
                match = True

            basic_auth_realm = f.get('basic_auth_realm', False)
            if basic_auth_realm and basic_auth_realm in res.headers.get('WWW-Authenticate', list()):
                match = True

            body_text = f.get('http_body', False)
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
    for cred in candidate['credentials']:
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
    user_field = None
    pass_field = None

    for f in candidate['form']:
        for field in f:
            if field == "username":
                user_field = f[field]
            elif field == "password":
                pass_field = f[field]
            else:
                data[field] = f[field]

    if csrf:
        csrf_field = candidate['csrf']
        data[csrf_field] = csrf

    for cred in candidate['credentials']:
        username = cred['username']
        password = cred['password']

        data[user_field] = username
        data[pass_field] = password
        
        logger.debug('check_form post data: %s' % data)
        
        res = None
        try:
            if sessionid:
                res = requests.post(req, data, cookies=sessionid, verify=False, proxies=proxy)
            else:
                res = requests.post(req, data, verify=False, proxies=proxy)
        except:
            logger.error("Failed to connect to %s" % req)
            return None

        logger.debug('check_form res.status_code: %i' % res.status_code)
        logger.debug('check_form res.text: %s' % res.text)

        if res and check_success(req, res, candidate, username, password):
            matches.append(cred)

    return matches

def check_success(req, res, candidate, username, password):
        match = True
        for s in candidate['success']:
            http_status = s.get('http_status', False)
            if http_status and not http_status == res.status_code:
                match = False

            http_body = s.get('http_body', False)
            if match and http_body and not http_body in res.text:
                match = False

        if match:
            logger.critical('[+] Found %s default cred %s:%s at %s' % (candidate['name'], username, password, req))
            return True
        else:
            logger.info('Invalid %s default cred %s:%s' % (candidate['name'], username, password))
            return False

            
def get_csrf_token(res, cred):
    name = cred.get('csrf', False)
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
    cookie = cred.get('sessionid', False)
    if cookie:
        try:
            value = res.cookies[cookie]
        except:
            logger.error("Failed to get %s cookie from %s" % (cookie, res.url))
            return False
        return { cookie: value }
    else:
        return False
        
def scan(urls, creds, threads, timeout, proxy):
    
    Thread = threading.Thread
    i = 0
    for req in urls:
        if i % 10 == 0 and i is not 0:
            logger.info('%i%% complete' % (i))
        while 1:
            if threading.activeCount() <= threads:
                t = Thread(target=do_scan, args=(req, creds, timeout, proxy))
                t.start()
                break

        i += 1

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
            check = globals()['check_' + match['type']]
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

            # Convert a single path to list with one element
            fix = list()
            paths = c.get('path', list())
            if isinstance(paths, str):
                x = list()
                x.append(paths)
                paths = x

            for path in paths:
                url = '%s://%s:%s%s' % (proto, target, port, path)
                urls.append(url)
                logger.debug('Rendered url: %s' % url)

    return urls

def main():
    print banner
    creds = load_creds()
    targets = list()
    proxy = None
    global logger

    start = time()

    ap = argparse.ArgumentParser(description='Default credential scanner v%i' % (__version__))
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
    args = ap.parse_args()
 
    setup_logging(args.verbose, args.debug, args.log)

    if not args.subnet and not args.targets:
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

    urls = build_target_list(targets, creds, args.name, args.category)

    if args.dryrun:
        dry_run(urls)

    logger.info('Scanning %i URLs' % len(urls))

    scan(urls, creds, args.threads, args.timeout, proxy)

    #elapsed = time() - start
    #print "Completed in %.2is" % (elapsed)
            
if __name__ == '__main__':
    main()
