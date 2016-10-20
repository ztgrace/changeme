#!/usr/bin/env python

import argparse
import requests
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import yaml
import os
import sys
import re
from netaddr import *
from lxml import html
import multiprocessing as mp
import logging
from logutils import colorize
from time import time
from urlparse import urlparse
from cerberus import Validator
from schema import schema
import urllib
import shodan
from libnmap.parser import NmapParser as np
import base64
from time import sleep
from copy import copy, deepcopy
import random


__version__ = "0.4.3"


logger = None
found_q = mp.Manager().Queue()
banner = """
  #####################################################
 #       _                                             #
 #   ___| |__   __ _ _ __   __ _  ___ _ __ ___   ___   #
 #  / __| '_ \ / _` | '_ \ / _` |/ _ \ '_ ` _ \ / _ \\  #
 # | (__| | | | (_| | | | | (_| |  __/ | | | | |  __/  #
 #  \___|_| |_|\__,_|_| |_|\__, |\___|_| |_| |_|\___|  #
 #                         |___/                       #
 #  v%s                                             #
 #  Default Credential Scanner                         #
  #####################################################
""" % __version__


class Fingerprint:

    def __init__(self, name, fp=dict()):
        self.name = name
        self.urls = set(fp.get('url'))
        self.http_status = fp.get('status')
        self.body_text = fp.get('body')
        self.basic_auth_realm = fp.get('basic_auth_realm', None)
        self.cookies = None
        cookies = fp.get('cookie')
        if cookies:
            self.cookies = cookies[0]
        self.headers = None
        headers = fp.get('headers', None)
        if headers:
            self.headers = headers[0]

        self.server_header = fp.get('server_header', None)

    def __hash__(self):
        return hash(self.name + ' '.join(self.urls))

    def __eq__(self, other):
        logger.debug("self.name: %s, other.name: %s" % (self.name, other.name))
        logger.debug("self.urls: %s, other.urls: %s" %
                     (','.join(self.urls), ','.join(other.urls)))
        # quick check
        if self.name == other.name:
            return True

        if (self.urls == other.urls and self.cookies == other.cookies and
                self.headers == other.headers):
            return True

        return False

    def __str__(self):
        return self.name

    def match(self, res):
        match = False

        if (self.basic_auth_realm and
                self.basic_auth_realm in res.headers.get('WWW-Authenticate', list())):
            logger.debug(
                '[Fingerprint.match] basic auth matched: %s' % self.body_text)
            match = True

        server = res.headers.get('Server', None)
        if self.server_header and server and self.server_header in server:
            logger.debug(
                '[Fingerprint.match] server header matched: %s' % self.body_text)
            match = True

        if self.body_text and re.search(self.body_text, res.text):
            match = True
            logger.debug('[Fingerprint.match] matched body: %s' %
                         self.body_text)
        elif self.body_text:
            logger.debug('[Fingerprint.match] body not matched')
            match = False

        return match


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

    if name and not cred['name'] == name:
        add = False
    elif category and not cred['category'] == category:
        add = False

    return add


def load_creds(name, category):
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
                        logger.error(
                            "[load_creds] %s: duplicate name %s" % (f, parsed['name']))
                    elif validate_cred(parsed, f):

                        if in_scope(name, category, parsed):
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
        logger.error("[validate_cred] Validation Error: %s, %s - %s" %
                     (f, e, v.errors[e]))

    return valid

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


def check_basic_auth(req, session, candidate, config, sessionid=False, csrf=False):
    matches = list()

    # Copy the session so successful creds don't affect other
    # requests in multi-cred scans
    orig_session = deepcopy(session)
    for cred in candidate['auth']['credentials']:
        username = cred.get('username', "")
        password = cred.get('password', "")
        base = get_base_url(req)

        for auth_url in candidate['auth']['url']:
            url = base + auth_url
            if password is None:
                password = ""

            try:
                # restore the original session
                session = deepcopy(orig_session)
                res = session.get(
                    url,
                    auth=HTTPBasicAuth(username, password),
                    verify=False,
                    proxies=config['proxy'],
                    timeout=config['timeout'],
                    headers=config['useragent'],
                )

            except Exception as e:
                logger.error(
                    "[check_basic_auth] Failed to connect to %s" % url)
                logger.debug("[check_basic_auth] Exception: %s" %
                             e.__str__().replace('\n', '|'))
                continue

            if check_success(req, res, candidate, username, password, candidate['auth'].get('base64', None)):
                matches.append(cred)

    return matches


def get_parameter_dict(auth):
    params = dict()
    data = auth.get('post', auth.get('get', None))
    for k in data.keys():
        if k not in ('username', 'password', 'url'):
            params[k] = data[k]

    return params


def get_base_url(req):
    parsed = urlparse(req)
    url = "%s://%s" % (parsed[0], parsed[1])
    return url


def check_post(req, session, candidate, config, sessionid=False, csrf=False):
    return check_http(req, session, candidate, config, sessionid, csrf)


def check_raw_post(req, session, candidate, config, sessionid=False, csrf=False):
    return check_http(req, session, candidate, config, sessionid, csrf)


def check_get(req, session, candidate, config, sessionid=False, csrf=False):
    return check_http(req, session, candidate, config, sessionid, csrf)


def render_creds(candidate, csrf):
    """
        Return a list of dicts with post/get data and creds.

        The list of dicts have a data element and a username and password
        associated with the data. The data will either be a dict if its a
        regular GET or POST and a string if its a raw POST.
    """
    posts = list()
    data = None
    b64 = candidate['auth'].get('base64', None)
    config = candidate['auth'].get('post', candidate['auth'].get(
        'get', candidate['auth'].get('raw_post', None)))

    if not candidate['auth']['type'] == 'raw_post':
        data = get_parameter_dict(candidate['auth'])

        if csrf:
            csrf_field = candidate['auth']['csrf']
            data[csrf_field] = csrf

        for cred in candidate['auth']['credentials']:
            username = ""
            password = ""
            if b64:
                username = base64.b64encode(cred['username'])
                password = base64.b64encode(cred['password'])
            else:
                username = cred['username']
                password = cred['password']

            data[config['username']] = username
            data[config['password']] = password

            posts.append({
                'data': data,
                'username': username,
                'password': password,
            })
    else:  # raw post
        for cred in candidate['auth']['credentials']:
            posts.append({
                'data': cred['raw'],
                'username': cred['username'],
                'password': cred['password'],
            })

    return posts


def check_http(req, session, candidate, config, sessionid=False, csrf=False):
    matches = list()
    data = None
    headers = dict()

    url = get_base_url(req)
    logger.debug('[check_http] base url: %s' % url)
    urls = candidate['auth']['url']
    if candidate['auth']['headers']:
        canheaders = candidate['auth']['headers']
        logger.debug('[check_http] candidate headers: %s' % canheaders)
        for head in canheaders:
            headers.update(head)
        
        headers.update(config['useragent'])
    else:
        headers = config['useragent']
    rendered = render_creds(candidate, csrf)
    for cred in rendered:
        logger.debug('[check_http] %s - %s:%s' % (
            candidate['name'],
            cred['username'],
            cred['username'],))

        res = None
        for u in urls:
            url = get_base_url(req) + u
            logger.debug("[check_http] url: %s" % url)
            logger.debug('[check_http] data: %s' % cred['data'])

            try:
                if candidate['auth']['type'] == 'post' or candidate['auth']['type'] == 'raw_post':
                    res = session.post(
                        url,
                        cred['data'],
                        cookies=sessionid,
                        verify=False,
                        proxies=config['proxy'],
                        timeout=config['timeout'],
                        headers=headers,
                    )
                else:
                    qs = urllib.urlencode(cred['data'])
                    url = "%s?%s" % (url, qs)
                    logger.debug("[check_http] url: %s" % url)
                    res = session.get(
                        url,
                        cookies=sessionid,
                        verify=False,
                        proxies=config['proxy'],
                        timeout=config['timeout'],
                        headers=headers,
                    )
            except Exception as e:
                logger.error("[check_http] Failed to connect to %s" % url)
                logger.debug("[check_http] Exception: %s" %
                             e.__str__().replace('\n', '|'))
                continue

            logger.debug('[check_http] res.status_code: %i' % res.status_code)
            logger.debug('[check_http] res.text: %s' % res.text)

            if res and check_success(req, res, candidate, cred['username'], cred['password'], candidate['auth'].get('base64', None)):
                matches.append(candidate)

    logger.debug('[check_http] matches: %s' % matches)
    return matches


def check_success(req, res, candidate, username, password, b64):
    match = True
    success = candidate['auth']['success']
    if b64:
        username = base64.b64decode(username)
        password = base64.b64decode(password)

    if success['status'] and not success['status'] == res.status_code:
        logger.debug('[check_success] status != res.status')
        match = False

    if match and success['body'] and not re.search(success['body'], res.text):
        logger.debug('[check_success] body text not found in response body')
        match = False

    if match:
        logger.critical('[+] Found %s default cred %s:%s at %s' %
                        (candidate['name'], username, password, req))
        found_q.put((candidate['name'], username, password, req))
        return True
    else:
        logger.info('[check_success] Invalid %s default cred %s:%s at %s' %
                    (candidate['name'], username, password, req))
        return False


def get_csrf_token(res, cred):
    name = cred['auth'].get('csrf', False)
    if name:
        tree = html.fromstring(res.content)
        try:
            csrf = tree.xpath('//input[@name="%s"]/@value' % name)[0]
        except:
            logger.error(
                "[get_csrf_token] failed to get CSRF token %s in %s" % (name, res.url))
            return False
        logger.debug('[get_csrf_token] got CSRF token %s: %s' % (name, csrf))
    else:
        csrf = False

    return csrf


def get_session_id(res, cred):
    cookie = cred['auth'].get('sessionid', False)
    logger.debug("[get_session_id] cookie: %s" % cookie)

    if cookie:
        try:
            value = res.cookies[cookie]
            logger.debug('[get_session_id] cookie value: %s' % value)
        except:
            logger.error(
                "[get_session_id] failed to get %s cookie from %s" % (cookie, res.url))
            return False
        return {cookie: value}
    else:
        logger.debug('[get_session_id] no cookie')
        return False


def get_cred(fp, creds):
    for cred in creds:
        if fp == Fingerprint(cred['name'], cred['fingerprint']):
            return cred


def scan(fingerprints, creds, config):

    procs = [mp.Process(target=do_scan, args=(fingerprints, creds, config))
             for i in range(config['threads'])]
    logger.debug("fp q size: %i " % fingerprints.qsize())
    for proc in procs:
        proc.start()

    for proc in procs:
        proc.join()


def do_scan(fingerprints, creds, config):
    matches = list()
    while not fingerprints.empty():
        fp = fingerprints.get_nowait()
        s = requests.Session()
        for url in fp.urls:
            try:
                # config['useragent'] is merged with fp.headers so 
                # that a hard-coded ua in a fp supersedes a manually set ua
                headers = config['useragent']
                if fp.headers:
                    headers.update(fp.headers)
                    logger.debug("merged headers: %s" % headers)
                res = s.get(url, timeout=config['timeout'], verify=False, proxies=config[
                            'proxy'], cookies=fp.cookies, headers=headers)
                logger.debug('[do_scan] %s - %i' % (url, res.status_code))
            except Exception as e:
                logger.debug('[do_scan] Failed to connect to %s' % (url,))
                logger.debug(e)
                continue

            match = fp.match(res)
            if match:
                logger.info("[do_scan] %s fingerprint matched %s" %
                            (url, fp.name))

                if not config['fingerprint']:
                    cred = get_cred(fp, creds)  # return matching cred
                    logger.debug("fp.name: %s, cred.name: %s" %
                                 (fp.name, cred['name']))
                    check = globals()['check_' + cred['auth']['type']]
                    csrf = get_csrf_token(res, cred)
                    sessionid = get_session_id(res, cred)

                    # Only scan if a sessionid is required and we can get it
                    if cred['auth'].get('sessionid') and not sessionid:
                        logger.debug("[do_scan] Missing required sessionid")
                        continue

                    # Only scan if a csrf token is required and we can get it
                    if cred['auth'].get('csrf', False) and not csrf:
                        logger.debug("[do_scan] Missing required csrf")
                        continue

                    cred_matches = check(url, s, cred, config, sessionid, csrf)
                    if cred_matches:
                        matches = matches + cred_matches
                        logger.debug('[do_scan] matches: %s' % cred_matches)
                else:  # fingerprinting only
                    matches.append(fp)

        fingerprints.task_done()
    return matches


def dry_run(fingerprints):
    logger.info("Dry run URLs:")
    while not fingerprints.empty():
        fp = fingerprints.get_nowait()
        for url in fp.urls:
            print url
        fingerprints.task_done()
    sys.exit()


def build_target_list(targets, creds, name, category):

    # Build target list
    fingerprints = mp.Manager().Queue()
    num_urls = 0
    for target in targets:
        for c in creds:
            urls = set()
            port = c.get('default_port', 80)

            if name and not name == c['name']:
                continue
            if category and not category == c['category']:
                continue
            if not isinstance(target, IPAddress) and ":" in target and not int(port) == int(target.split(":")[1]):
                continue
            elif not isinstance(target, IPAddress):
                # strip the port off
                target = target.split(":")[0]

            ssl = c.get('ssl', False)
            if ssl:
                proto = 'https'
            else:
                proto = 'http'

            fp = Fingerprint(c['name'], fp=c['fingerprint'])

            for path in fp.urls:
                url = '%s://%s%s' % (proto, target, port, path)
                urls.add(url)
                num_urls += 1
                logger.debug('[build_target_list] Rendered url: %s' % url)

            fp.urls = urls
            fingerprints.put(fp)

    return {'fingerprints': fingerprints, 'num_urls': num_urls}


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


def file_exists(f):
    if not os.path.isfile(f):
        logger.error("File %s not found" % f)
        sys.exit()


def report_creds(found_q, output):
    logger.critical("Found %i credentials" % found_q.qsize())
    if output:
        with open(output, "wb") as fout:
            while not found_q.empty():
                fout.write(','.join(map(str, found_q.get())) + '\n')

        logger.info("Wrote output to %s" % output)


def main():
    print banner
    targets = set()
    proxy = None
    global logger
    config = dict()
    global found_q

    start = time()

    ap = argparse.ArgumentParser(description='Default credential scanner v%s' % (__version__))
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
    ap.add_argument('--targets', type=str, help='File of targets to scan')
    ap.add_argument('--threads', '-t', type=int, help='Number of threads, default=10', default=10)
    ap.add_argument('--timeout', type=int, help='Timeout in seconds for a request, default=10', default=10)
    ap.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    ap.add_argument('--validate', action='store_true', help='Validate creds files')
    ap.add_argument('--nmap', '-x', type=str, help='Nmap XML file to parse')
    ap.add_argument('--useragent', '-ua' , type=str, help="User agent string to use")
    args = ap.parse_args()

    setup_logging(args.verbose, args.debug, args.log)

    if (not args.subnet and not args.targets and not args.validate and
            not args.contributors and not args.dump and
            not args.shodan_query and not args.nmap):
        logger.error('Need to supply a subnet, targets file or shodan query.')
        ap.print_help()
        sys.exit()

    if args.subnet:
        for ip in IPNetwork(args.subnet).iter_hosts():
            targets.add(ip)

    if args.targets:
        file_exists(args.targets)
        with open(args.targets, 'r') as fin:
            targets = [x.strip('\n') for x in fin.readlines()]

    if args.shodan_query:
        api = shodan.Shodan(args.shodan_key)
        results = api.search(args.shodan_query)
        for r in results['matches']:
            targets.add(r['ip_str'])

    if args.nmap:
        file_exists(args.nmap)
        report = np.parse_fromfile(args.nmap)
        logger.info('Loaded %i hosts from %s' % (len(report.hosts), args.nmap))
        for h in report.hosts:
            for s in h.services:
                targets.add('%s:%s' % (h.address, s.port))

    logger.info('Loaded %i targets' % len(targets))

    if args.proxy and re.match('^https?://[0-9\.]+:[0-9]{1,5}$', args.proxy):
        proxy = {'http': args.proxy,
                 'https': args.proxy}
        logger.info('Setting proxy to %s' % args.proxy)
    elif args.proxy:
        logger.error('Invalid proxy, must be http(s)://x.x.x.x:8080')
        sys.exit()

    if args.validate:
        load_creds()
        sys.exit()

    creds = load_creds(args.name, args.category)

    if args.contributors:
        print_contributors(creds)

    if args.dump:
        print_creds(creds)

    if args.fingerprint:
        # Need to drop the level to INFO to see the fp messages
        logger.setLevel(logging.INFO)

    tlist = build_target_list(targets, creds, args.name, args.category)
    fingerprints = tlist['fingerprints']

    if args.dryrun:
        dry_run(fingerprints)

    logger.info('Scanning %i URLs' % tlist['num_urls'])

    config = {
        'threads':  args.threads,
        'timeout': args.timeout if args.timeout else 10,
        'proxy': proxy,
        'fingerprint': args.fingerprint,
        'useragent': {'User-Agent': args.useragent if args.useragent else get_useragent()}
    }

    if config['threads'] > tlist['num_urls']:
        config['threads'] = tlist['num_urls']

    scan(fingerprints, creds, config)
    report_creds(found_q, args.output)

if __name__ == '__main__':
    main()
