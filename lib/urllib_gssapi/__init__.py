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
        self.retried = 0
        self.context = None

    neg_regex = re.compile('(?:.*,)*\s*Negotiate\s*([^,]*),?', re.I)

    def negotiate_value(self, headers):
        """checks for "Negotiate" in proper auth header
        """
        authreqs = headers.get(self.auth_header).split(',')

        if authreqs:
            for authreq in authreqs:
                mo = self.neg_regex.search(authreq)
                if mo:
                    return b64decode(mo.group(1))
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

        remote_name = gssapi.Name("HTTP@%s" % domain,
                                  gssapi.NameType.hostbased_service)
        self.context = gssapi.SecurityContext(usage="initiate",
                                              name=remote_name)
        log.debug("created GSSAPI context")

        response = self.context.step(neg_value)
        log.debug("successfully stepped context")
        return "Negotiate %s" % b64encode(response).decode()

    def authenticate_server(self, headers):
        neg_value = self.negotiate_value(headers)
        if neg_value is None:
            log.critical("mutual auth failed. No negotiate header")
            return None

        token = self.context.step(neg_value)
        if token is not None:
            log.critical(
                "mutual auth failed: authGSSClientStep returned a token")
            pass

    def clean_context(self):
        if self.context is not None:
            log.debug("cleaning context")
            self.context = None

    def http_error_auth_reqed(self, host, req, headers):
        neg_value = self.negotiate_value(headers)  # Check for auth_header
        if neg_value is not None:
            if not self.retried > 0:
                return self.retry_http_gssapi_auth(req, headers, neg_value)
            else:
                return None
        else:
            self.retried = 0

    def retry_http_gssapi_auth(self, req, headers, neg_value):
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

        except gssapi.exceptions.GSSError as e:
            self.clean_context()
            self.retried = 0
            log.critical("GSSAPI Error: %s" % e.gen_message())
            return None

        self.clean_context()
        self.retried = 0


class ProxySPNEGOAuthHandler(BaseHandler, AbstractSPNEGOAuthHandler):
    """SPNEGO Negotiation handler for HTTP proxy auth
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


class HTTPSPNEGOAuthHandler(BaseHandler, AbstractSPNEGOAuthHandler):
    """SPNEGO Negotiation handler for HTTP auth
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
