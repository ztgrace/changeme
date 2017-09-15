import csv
import jinja2
import json
import logging
import os
from tabulate import tabulate
from tempfile import NamedTemporaryFile


class Report:
    def __init__(self, queue, output):
        self.results = self._convert_q2list(queue)
        self.output = output
        self.logger = logging.getLogger('changeme')

    def render_csv(self,):
        with open(self.output, 'w') as fout:
            fieldnames = ["name", "username", "password", "target"]
            writer = csv.DictWriter(
                fout,
                quoting=csv.QUOTE_ALL,
                fieldnames=fieldnames,
                extrasaction='ignore'
            )
            writer.writeheader()
            writer.writerows(self.results)

        self.logger.critical("%i credentials written to %s" % (len(self.results), self.output))

    def render_json(self):
        # convert the Target classes to a string so it can be json'd
        res = list()
        for r in self.results:
            t = r['target']
            r['target'] = str(t)
            res.append(r)

        results = dict()
        results["results"] = res
        j = json.dumps(results)
        with open(self.output, 'w') as fout:
            fout.write(j)

        self.logger.critical("%i credentials written to %s" % (len(self.results), self.output))

    def print_results(self):
        if len(self.results) > 0:
            print("")
            print("")
            self.logger.critical('Found %i default credentials' % len(self.results))
            print("")
            print(tabulate(self.results, headers={'name': 'Name',
                                                  'username': 'Username',
                                                  'password': 'Password',
                                                  'target': 'Target',
                                                  'evidence': 'Evidence'}))
            print("")

    def render_html(self):
        self.logger.debug('templatePATH: %s' % self.get_template_path())
        template_loader = jinja2.FileSystemLoader(searchpath=self.get_template_path())
        template_env = jinja2.Environment(loader=template_loader)
        report_template = template_env.get_template('report.j2')
        report = report_template.render({'found': self.results})
        print report

        with open(self.output, 'w') as fout:
            fout.write(report)

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
