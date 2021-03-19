# Copyright (c) 2016 Will Thames <will@thames.id.au>
# Copyright (c) 2018 The Python GSSAPI Team
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import unittest

import urllib_gssapi

try:
    # python3
    import urllib.request as urllib_request
except ImportError:
    # python2
    import urllib2 as urllib_request


class TestUrls(unittest.TestCase):
    def setUp(self):
        handler = urllib_gssapi.HTTPSPNEGOAuthHandler()
        opener = urllib_request.build_opener(handler)
        urllib_request.install_opener(opener)

    def test_non_SPNEGO(self):
        r = urllib_request.urlopen("https://mivehind.net/")
        r.read()
