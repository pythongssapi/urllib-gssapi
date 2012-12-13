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

from __future__ import print_function

import re
import logging
import sys

try:
    from urlparse import urlparse
    from urllib2 import BaseHandler, HTTPPasswordMgr
except ImportError:
    from urllib.parse import urlparse
    from urllib.request import BaseHandler, HTTPPasswordMgr

try:
    import kerberos as k
except ImportError:
    if sys.platform == 'win32':
        import kerberos_sspi as k
    else:
        raise SystemExit("Could not import kerberos library. Please ensure "
                         "it is installed")


log = logging.getLogger("http_kerberos_auth_handler")


class AbstractKerberosAuthHandler:
    """auth handler for urllib2 that does Kerberos
       HTTP Negotiate Authentication"""

    def __init__(self, password_mgr=None):
        """Initialize an instance of a AbstractKerberosAuthHandler."""
        self.retried = 0
        self.context = None

        if password_mgr is None:
            password_mgr = HTTPPasswordMgr()
        self.passwd = password_mgr
        self.add_password = self.passwd.add_password

    neg_regex = re.compile('(?:.*,)*\s*Negotiate\s*([^,]*),?', re.I)

    def negotiate_value(self, headers):
        """checks for "Negotiate" in proper auth header
        """
        authreqs = headers.get(self.auth_header).split(',')

        if authreqs:
            for authreq in authreqs:
                mo = self.neg_regex.search(authreq)
                if mo:
                    return mo.group(1)
                else:
                    log.debug("regex failed on: %s" % authreq)

        else:
            log.debug("%s header not found" % self.auth_header)

        return None

    def generate_request_header(self, req, headers, neg_value):
        self.retried += 1
        log.debug("retry count: %d" % self.retried)

        host = urlparse(req.get_full_url()).netloc
        log.debug("urlparse(req.get_full_url()).netloc returned %s" % host)

        domain = host.rsplit(':', 1)[0]

        # Check for alternate credentials for the requested url
        user, password = self.passwd.find_user_password(None,
                                                        req.get_full_url())
        kwargs = dict()
        if user and password:
            kwargs['principal'] = user
            kwargs['password'] = password

        result, self.context = k.authGSSClientInit("HTTP@%s" % domain,
                                                   **kwargs)

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

        result = k.authGSSClientStep(self.context, neg_value)

        if result < 1:
            # this is a critical security warning
            # should change to a raise --Tim
            log.critical("mutual auth failed: authGSSClientStep "
                         "returned result %d" % result)
            pass

    def clean_context(self):
        if self.context is not None:
            log.debug("cleaning context")
            k.authGSSClientClean(self.context)
            self.context = None

    def http_error_auth_reqed(self, host, req, headers):
        neg_value = self.negotiate_value(headers)  # Check for auth_header
        if neg_value is not None:
            if not self.retried > 0:
                return self.retry_http_kerberos_auth(req, headers, neg_value)
            else:
                return None
        else:
            self.retried = 0

    def retry_http_kerberos_auth(self, req, headers, neg_value):
        try:
            neg_hdr = self.generate_request_header(req, headers, neg_value)

            if neg_hdr is None:
                log.debug("neg_hdr was None")
                return None

            req.add_unredirected_header(self.authz_header, neg_hdr)
            resp = self.parent.open(req)

            if resp.getcode() != 200:
                self.authenticate_server(resp.info())

            return resp

        except k.GSSError as e:
            self.clean_context()
            self.retried = 0
            log.critical("GSSAPI Error: %s/%s" % (e[0][0], e[1][0]))
            return None

        self.clean_context()
        self.retried = 0


class ProxyKerberosAuthHandler(BaseHandler, AbstractKerberosAuthHandler):
    """Kerberos Negotiation handler for HTTP proxy auth
    """

    authz_header = 'Proxy-Authorization'
    auth_header = 'proxy-authenticate'

    handler_order = 480  # before Digest auth

    def http_error_407(self, req, fp, code, msg, headers):
        log.debug("inside http_error_407")
        host = urlparse(req.get_full_url()).netloc
        retry = self.http_error_auth_reqed(host, req, headers)
        self.retried = 0
        return retry


class HTTPKerberosAuthHandler(BaseHandler, AbstractKerberosAuthHandler):
    """Kerberos Negotiation handler for HTTP auth
    """

    authz_header = 'Authorization'
    auth_header = 'www-authenticate'

    handler_order = 480  # before Digest auth

    def http_error_401(self, req, fp, code, msg, headers):
        log.debug("inside http_error_401")
        host = urlparse(req.get_full_url()).netloc
        retry = self.http_error_auth_reqed(host, req, headers)
        self.retried = 0
        return retry
