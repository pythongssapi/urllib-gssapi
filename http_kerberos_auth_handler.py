#!/usr/bin/python

# urllib2 with kerberos proof of concept
# Copyright 2008 Lime Spot LLC

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# A copy of the GNU General Public License can be found at
# <http://www.gnu.org/licenses/>.

import re
import logging
import sys
import urllib2 as u2

import kerberos as k

def getLogger():
    log = logging.getLogger("http_kerberos_auth_handler")
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(formatter)
    log.addHandler(handler)
    return log

log = getLogger()

class HTTPKerberosAuthHandler(u2.BaseHandler):
    """auth handler for urllib2 that does Kerberos HTTP Negotiate Authentication
    """

    rx = re.compile('(?:.*,)*\s*Negotiate\s*([^,]*),?', re.I)
    handler_order = 480  # before Digest auth

    def negotiate_value(self, headers):
        authreq = headers.get('www-authenticate', None)

        if authreq:
            mo = HTTPKerberosAuthHandler.rx.search(authreq)
            if mo:
                return mo.group(1)
            else:
                log.debug("regex failed on: %s" % authreq)

        else:
            log.debug("www-authenticate header not found")

        return None

    def __init__(self):
        self.retried = 0
        self.context = None

    def generate_request_header(self, req, headers):
        neg_value = self.negotiate_value(headers)
        if neg_value is None:
            self.retried = 0
            return None

        if self.retried > 5:
            raise HTTPError(req.get_full_url(), 401, "kerberos negotiate auth failed",
                            headers, None)

        self.retried += 1

        log.debug("req.get_host() returned %s" % req.get_host())
        result, self.context = k.authGSSClientInit("HTTP@%s" % req.get_host())

        if result < 1:
            log.warning("authGSSClientInit returned result %d" % result)
            return None

        log.debug("authGSSClientInit() succeeded")

        result = k.authGSSClientStep(self.context, neg_value)

        if result < 0:
            log.warning("authGSSClientStep returned result %d" % result)
            return None

        log.debug("authGSSClientStep() succeeded")

        response = k.authGSSClientResponse(self.context)
        log.debug("authGSSClientResponse() succeeded")
        
        return "Negotiate %s" % response

    def authenticate_server(self, headers):
        neg_value = self.negotiate_value(headers)
        if neg_value is None:
            log.critical("mutual auth failed. No negotiate header")
            return None

        if k.authGSSClientStep(self.context, neg_value) < 1:
            log.critical("mutual auth failed: authGSSClientStep returned result %d" % result)

    def clean_context(self):
        if self.context is not None:
            k.authGSSClientClean(self.context)

    def http_error_401(self, req, fp, code, msg, headers):
        log.debug("inside http_error_401")
        try:
            neg_hdr = self.generate_request_header(req, headers)

            if neg_hdr is None:
                log.debug("neg_hdr was None")
                return None

            req.add_unredirected_header('Authorization', neg_hdr)
            resp = self.parent.open(req)

            self.authenticate_server(resp.info())

            return resp
        
        finally:
            self.clean_context()

def test():
    log.setLevel(logging.DEBUG)
    log.info("starting test")
    opener = u2.build_opener()
    opener.add_handler(HTTPKerberosAuthHandler())
    resp = opener.open(sys.argv[1])
    print dir(resp), resp.info(), resp.code
    

if __name__ == '__main__':
    test()

