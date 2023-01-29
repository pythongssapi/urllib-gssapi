# urllib/urllib2 support for GSSAPI/SPNEGO

# Copyright 2008 Lime Nest LLC
# Copyright 2008 Lime Spot LLC
# Copyright 2018 The Python GSSAPI Team

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

from base64 import b64encode, b64decode

import gssapi

try:
    from urlparse import urlparse
    from urllib2 import BaseHandler
except ImportError:
    from urllib.parse import urlparse
    from urllib.request import BaseHandler

log = logging.getLogger("http_gssapi_auth_handler")


class AbstractSPNEGOAuthHandler:
    """urllib/urllib2 auth handler performing GSSAPI/SPNEGO HTTP Negotiate
Authentication

    """

    def __init__(self):
        """Initialize an instance of a AbstractSPNEGOAuthHandler."""
        self.pre_auth = False
        self.context = None

    neg_regex = re.compile(r'(?:.*,)*\s*Negotiate\s*([^,]*),?', re.I)

    def negotiate_value(self, headers):
        """checks for "Negotiate" in proper auth header
        """
        authreqs = headers.get(self.auth_header).split(',')

        if not authreqs:
            log.debug("%s header not found" % self.auth_header)
            return None

        for authreq in authreqs:
            mo = self.neg_regex.search(authreq)
            if mo:
                return b64decode(mo.group(1))
            log.debug("regex failed on: %s" % authreq)

        return None

    def generate_request_header(self, req, neg_value):
        if not self.context:
            host = urlparse(req.get_full_url()).netloc
            log.debug("urlparse(req.get_full_url()).netloc returned %s" % host)

            domain = host.rsplit(':', 1)[0]

            remote_name = gssapi.Name("HTTP@%s" % domain, gssapi.NameType.hostbased_service)
            self.context = gssapi.SecurityContext(usage="initiate", name=remote_name)
            log.debug("created GSSAPI context")

        response = self.context.step(neg_value)
        log.debug("successfully stepped context")
        if not response: return None
        return "Negotiate %s" % b64encode(response).decode()

    def http_error_auth_reqed(self, host, req, headers):
        self.context = None
        rcode = self.auth_code
        neg_value = self.negotiate_value(headers)
        if neg_value is None: return None

        while (rcode == self.auth_code):
            neg_hdr = self.generate_request_header(req, neg_value)
            req.add_unredirected_header(self.authz_header, neg_hdr)
            if req.data and hasattr(req.data, 'seek'): req.data.seek(0)
            resp = self.parent.open(req)
            rcode = resp.getcode()
            neg_value = self.negotiate_value(resp.info())

        self.context.step(neg_value)
        self.pre_auth = self.context.complete

        return resp

    def http_request(self, req):
        if self.pre_auth:
            self.context = None
            neg_hdr = self.generate_request_header(req, None)
            req.add_unredirected_header(self.authz_header, neg_hdr)
        return req

class ProxySPNEGOAuthHandler(BaseHandler, AbstractSPNEGOAuthHandler):
    """SPNEGO Negotiation handler for HTTP proxy auth
    """

    authz_header = 'Proxy-Authorization'
    auth_header = 'proxy-authenticate'
    auth_code = 407

    handler_order = 480  # before Digest auth

    def http_error_407(self, req, fp, code, msg, headers):
        log.debug("inside http_error_407")
        host = urlparse(req.get_full_url()).netloc
        retry = self.http_error_auth_reqed(host, req, headers)
        return retry

class HTTPSPNEGOAuthHandler(BaseHandler, AbstractSPNEGOAuthHandler):
    """SPNEGO Negotiation handler for HTTP auth
    """

    authz_header = 'Authorization'
    auth_header = 'www-authenticate'
    auth_code = 401

    handler_order = 480  # before Digest auth

    def http_error_401(self, req, fp, code, msg, headers):
        log.debug("inside http_error_401")
        host = urlparse(req.get_full_url()).netloc
        retry = self.http_error_auth_reqed(host, req, headers)
        return retry
