import csv
import logging


class Report:
    def __init__(self, queue, output):
        self.results = self._convert_q2list(queue)
        self.output = output
        self.logger = logging.getLogger('changeme')


    def render_csv(self,):
        with open(self.output, 'wb') as fout:
            fieldnames = ["name", "username", "password", "url"]
            writer = csv.DictWriter(
                fout,
                quoting=csv.QUOTE_ALL,
                fieldnames=fieldnames,
                extrasaction='ignore'
            )
            writer.writeheader()
            writer.writerows(self.results)

        self.logger.critical("%i credentials written to %s" % (len(self.results), self.output))

    def _convert_q2list(self, q):
        items = list()
        while not q.empty():
            i = q.get()
            items.append(i)

        # Restore queue
        for i in items:
            q.put(i)

        return items