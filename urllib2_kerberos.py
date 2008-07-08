#!/usr/bin/python

# urllib2 with kerberos proof of concept

# Copyright 2008 Lime Nest LLC
# Copyright 2008 Lime Spot LLC

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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

        if self.retried > 0:
            raise u2.HTTPError(req.get_full_url(), 401, "kerberos negotiate auth failed",
                               headers, None)

        self.retried += 1

        log.debug("retry count: %d" % self.retried)

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
            log.debug("cleaning context")
            k.authGSSClientClean(self.context)
            self.context = None

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

        except k.GSSError, e:
            log.critical("GSSAPI Error: %s/%s" % (e[0][0], e[1][0]))
            return None
        
        finally:
            self.clean_context()
            self.retried = 0

def test():
    log.setLevel(logging.DEBUG)
    log.info("starting test")
    opener = u2.build_opener()
    opener.add_handler(HTTPKerberosAuthHandler())
    resp = opener.open(sys.argv[1])
    print dir(resp), resp.info(), resp.code
    

if __name__ == '__main__':
    test()

