import csv
import json
import logging
from tabulate import tabulate


class Report:
    def __init__(self, queue, output):
        self.results = self._convert_q2list(queue)
        self.output = output
        self.logger = logging.getLogger('changeme')

    def render_csv(self,):
        with open(self.output, 'wb') as fout:
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
        results = dict()
        results["results"] = self.results
        j = json.dumps(results)
        with open(self.output, 'wb') as fout:
            fout.write(j)

        self.logger.critical("%i credentials written to %s" % (len(self.results), self.output))

    def print_results(self):
        if len(self.results) > 0:
            print
            print
            self.logger.critical('Found %i default credentials' % len(self.results))
            print
            print tabulate(self.results, headers={'name': 'Name',
                                                  'username': 'Username',
                                                  'password': 'Password',
                                                  'target': 'Target',
                                                  'evidence': 'Evidence'})
            print

    def _convert_q2list(self, q):
        items = list()
        while not q.qsize() == 0:
            i = q.get()
            items.append(i)

        # Restore queue
        for i in items:
            q.put(i)

        return items