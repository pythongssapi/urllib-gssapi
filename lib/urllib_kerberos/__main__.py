from __future__ import print_function

import logging
import sys

from . import HTTPKerberosAuthHandler, log

try:
    import urllib.request as urllib_request
except ImportError:
    import urllib2 as urllib_request


def test():
    logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s',
                        level=logging.DEBUG)
    log.info("starting test")
    opener = urllib_request.build_opener()
    opener.add_handler(HTTPKerberosAuthHandler())
    resp = opener.open(sys.argv[1])
    log.info("headers: " + str(resp.headers))
    log.info("code: " + str(resp.code))
    log.info("content: " + str(resp.readlines()))


if __name__ == '__main__':
    test()
