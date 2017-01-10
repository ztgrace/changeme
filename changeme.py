#!/usr/bin/env python

from changeme import core, version
from load_creds import Credentials
from netaddr import *
import argparse
import os
import re
import sys

def get_custom_creds(file):
    if not os.path.isfile(file):
        print "File %s not found" % file
        return False

    custom_creds = list()
    with open(file, 'r') as fin:
        for x in fin.readlines():
            username, password = x.strip('\n').split('/', 1)
            custom_creds.append(
                {
                    'username' : username,
                    'password' : password
                }
            )
    return custom_creds


def build_targets_list(target, file):
    targets_list = list()
    if target:
        for ip in IPNetwork(target).iter_hosts():
            targets_list.append(ip)

    if file:
        if not os.path.isfile(file):
            print "File %s not found" % file
            return False
        with open(file, 'r') as fin:
            targets_list = [x.strip('\n') for x in fin.readlines()]

    return targets_list


if __name__ == '__main__':

    print core.banner(version.__version__)

    ap = argparse.ArgumentParser(description='Default credential scanner v%s' % version.__version__)

    # Specify a particular protocol / category / service
    ap.add_argument('--protocol', choices=['ftp', 'http' , 'mssql', 'ssh', 'telnet'], help='Protocol of default creds to scan for', default=None)
    ap.add_argument('--category', '-c', choices=['webcam', 'web', 'phone', 'printer'], help='Category of default creds to scan for', default=None)
    ap.add_argument('--name', '-n', type=str, help='Narrow testing to the supplied credential name', default=None)

    # Targets to launch scan
    ap.add_argument('--target', type=str, help='Subnet or IP to scan')
    ap.add_argument('--targets', type=str, help='File of targets to scan (IP or IP:PORT)', default=None)
    ap.add_argument('--port', type=int, help='Custom port to connect', default=None)
    ap.add_argument('--ssl', action='store_true', help='Use ssl', default=None)
    ap.add_argument('--creds', type=str, help='File of custom credentials to check (login/password)', default=None)
    
    # Log and output
    ap.add_argument('--proxy', '-p', type=str, help='HTTP(S) Proxy', default=None)
    ap.add_argument('--log', '-l', type=str, help='Write logs to logfile', default=None)
    # ap.add_argument('--output', '-o', type=str, help='Name of file to write CSV results', default=None)
    
    # Verbosity
    ap.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    ap.add_argument('--debug', '-d', action='store_true', help='Debug output')

    # Advanced options
    ap.add_argument('--timeout', type=int, help='Timeout in seconds for a request, default=10', default=10)
    ap.add_argument('--useragent', '-ua', type=str, help="User agent string to use")
    ap.add_argument('--delay', '-dl', type=int, help="Specify a delay in milliseconds to avoid 429 status codes default=500", default=500)
    # ap.add_argument('--threads', '-t', type=int, help='Number of threads, default=10', default=10)
    # ap.add_argument('--nmap', '-x', type=str, help='Nmap XML file to parse')
    
    args = ap.parse_args()

    if (not args.target and not args.targets):
        ap.print_help()

    proxy = None
    if args.proxy and re.match('^https?://[0-9\.]+:[0-9]{1,5}$', args.proxy):
        proxy = {
            'http': args.proxy,
            'https': args.proxy
        }
    elif args.proxy:
        print '[!] Invalid proxy, must be http(s)://x.x.x.x:8080'
        sys.exit()

    custom_cred = None
    if args.creds:
        custom_cred = get_custom_creds(args.creds)
        if not custom_cred:
            sys.exit()

    targets_list = build_targets_list(target=args.target, file=args.targets)
    if targets_list:
        # Load credential from filesystem
        creds = Credentials().load_creds(args.protocol, args.name, args.category)

        # Run main function
        pwd_found = core.run_changeme(
            protocol=args.protocol,
            category=args.category,
            name=args.name,
            targets=targets_list, 
            port=args.port,
            ssl=args.ssl,
            proxy=proxy,
            log=args.log,
            verbose=args.verbose,
            debug=args.debug,
            timeout=args.timeout,
            useragent=args.useragent,
            delay=args.delay,
            creds=creds,
            custom_creds=custom_cred
        )

        # print all passwords found !
        # if pwd_found:
        #     print '\n[+] Password Found !'
        #     for pwd in pwd_found:
        #         for p in pwd:
        #             print '%s: %s' % (p.capitalize(), pwd[p])
        #         print
