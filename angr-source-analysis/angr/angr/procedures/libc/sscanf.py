import logging

from angr.procedures.stubs.format_parser import ScanfFormatParser

l = logging.getLogger(name=__name__)

class sscanf(ScanfFormatParser):
    #pylint:disable=arguments-differ,unused-argument
    def run(self, data, fmt):
        fmt_str = self._parse(1)
        items = fmt_str.interpret(2, self.arg, addr=data)
        return items
