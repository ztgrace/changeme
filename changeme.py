#!/usr/bin/env python

from changeme import core, scan_engine, version
from changeme.scan_engine import ScanEngine
import argparse


def main():
    print core.banner(version.__version__)

    """
    targets = set()
    proxy = None
    config = dict()
    global found_q

    start = time()
    """

    config = core.config()

    s = ScanEngine()
    s.scan(list(), list(), config)


    """
    TODO: incorporate all of the arg checking

    if args.subnet:
        for ip in IPNetwork(args.subnet).iter_hosts():
            targets.add(ip)

    if args.targets:
        with open(args.targets, 'r') as fin:
            targets = [x.strip('\n') for x in fin.readlines()]

    if args.target:
        targets.add(args.target)

    if args.shodan_query:
        api = shodan.Shodan(args.shodan_key)
        results = api.search(args.shodan_query)
        for r in results['matches']:
            targets.add(r['ip_str'])

    if args.nmap:
        report = np.parse_fromfile(args.nmap)
        logger.info('Loaded %i hosts from %s' % (len(report.hosts), args.nmap))
        for h in report.hosts:
            for s in h.services:
                targets.add('%s:%s' % (h.address, s.port))

    logger.info('Loaded %i targets' % len(targets))


    if args.validate:
        load_creds(args.name, args.category)
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
        'delay': args.delay * .001,
        'threads':  args.threads,
        'timeout': args.timeout if args.timeout else 10,
        'proxy': proxy,
        'fingerprint': args.fingerprint,
        'useragent': {'User-Agent': args.useragent if args.useragent else get_useragent()}
    }

    if config['threads'] > tlist['num_urls']:
        config['threads'] = tlist['num_urls']

    scan(fingerprints, creds, config)
    report = Report(found_q, args.output)
    logger.critical("Found %i credentials" % len(report.results))
    if args.output:
        report.render_csv()
        report.render_html()
    """

if __name__ == '__main__':
    main()
