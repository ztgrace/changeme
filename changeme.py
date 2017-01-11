#!/usr/bin/env python

from changeme import core, version
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

    config = core.Config()
    creds = core.load_creds(config)

    if config.contributors:
        core.print_contributors(creds)
        quit()

    if config.dump:
        core.print_creds(creds)
        quit()

    if not config.validate:
        s = ScanEngine(creds, config)
        s.scan()


    """
    TODO: incorporate all of the arg checking

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
