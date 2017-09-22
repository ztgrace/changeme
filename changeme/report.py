import csv
from copy import deepcopy
from datetime import datetime
import jinja2
import json
import logging
import os
import re
import sys
from tabulate import tabulate


class Report:
    def __init__(self, queue, output):
        self.results = self._convert_q2list(queue)
        self.output = output
        self.logger = logging.getLogger('changeme')

    def render_csv(self,):
        fname = self.output
        if not re.match(r'.*\.csv$', fname):
            fname += ".csv"

        with open(fname, 'w') as fout:
            fieldnames = ["name", "username", "password", "target"]
            writer = csv.DictWriter(
                fout,
                quoting=csv.QUOTE_ALL,
                fieldnames=fieldnames,
                extrasaction='ignore'
            )
            writer.writeheader()
            writer.writerows(self.results)

        self.logger.critical("%i credentials written to %s" % (len(self.results), fname))

    def render_json(self):
        # convert the Target classes to a string so it can be json'd
        res = deepcopy(self.results)
        for r in res:
            t = r['target']
            r['target'] = str(t)

        results = dict()
        results["results"] = res
        j = json.dumps(results)
        fname = self.output
        if not re.match(r'.*\.json$', fname):
            fname += ".json"

        with open(fname, 'w') as fout:
            fout.write(j)

        self.logger.critical("%i credentials written to %s" % (len(self.results), fname))

    def print_results(self):
        if len(self.results) > 0:
            results = deepcopy(self.results)
            for r in results:
                if 'http' in r['target'].protocol:
                    r['evidence'] = ''

            print("")
            print("")
            self.logger.critical('Found %i default credentials' % len(self.results))
            print("")
            print(tabulate(results, headers={'name': 'Name',
                                             'username': 'Username',
                                             'password': 'Password',
                                             'target': 'Target',
                                             'evidence': 'Evidence'}))

            print("")
        else:
            print("No default credentials found")

    def render_html(self):
        template_loader = jinja2.FileSystemLoader(searchpath=self.get_template_path())
        template_env = jinja2.Environment(loader=template_loader)
        report_template = template_env.get_template('report.j2')
        cli = ' '.join(sys.argv)
        timestamp = datetime.now()
        report = report_template.render({'found': self.results, 'cli': cli, 'timestamp': timestamp})

        fname = self.output
        if not re.match(r'.*\.html$', fname):
            fname += ".html"

        with open(fname, 'w') as fout:
            fout.write(report)

        self.logger.critical("%i credentials written to %s" % (len(self.results), fname))

    @staticmethod
    def get_template_path():
        PATH = os.path.dirname(os.path.abspath(__file__))
        template_path = os.path.join(PATH, 'templates')
        return template_path

    def _convert_q2list(self, q):
        items = list()
        while not q.qsize() == 0:
            i = q.get()
            items.append(i)

        # Restore queue
        for i in items:
            q.put(i)

        return items
