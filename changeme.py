#!/usr/bin/env python

from changeme import core, version
from changeme.scan_engine import ScanEngine
import logging
from logutils import colorize
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import sys


def main():
    print core.banner(version.__version__)

    """
    targets = set()
    proxy = None
    config = dict()
    global found_q

    start = time()
    """

    init_logging()
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
def init_logging(verbose=False, debug=False, logfile=None):
    """
    Logging levels:
        - Critical: Default credential found
        - Error: error in the program
        - Warning: Verbose data
        - Info: more verbose
        - Debug: Extra info for debugging purposes
    """
    # Set up our logging object
    logger = logging.getLogger('changeme')

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
        '[%(asctime)s][%(module)s][%(funcName)s] %(message)s', datefmt='%H:%M:%S')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # Adjust the loggers for requests and urllib3
    logging.getLogger('requests').setLevel(logging.ERROR)
    logging.getLogger('urllib3').setLevel(logging.ERROR)
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    return logger

if __name__ == '__main__':
    main()
