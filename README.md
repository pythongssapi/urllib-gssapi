# urllib\_gssapi

urllib\_gssapi is a urllib backend for GSSAPI/SPNEGO authentication to HTTP
servers.

## Usage

urllib\_gssapi replaces urllib\_kerberos, and behaves the same way - just
rename to HTTPSPNEGOAuthHandler.

With an array of your other handlers (or just an empty one):

### Python 2

```Python
import urllib2
import urllib_gssapi

handlers.append(urllib_gssapi.HTTPSPNEGOAuthHandler())

opener = urllib2.build_opener(*handlers)
urllib2.install_opener(opener)
request = urllib2.Request(url, data)
```

### Python 3

```Python
import urllib.request
import urllib_gssapi

handlers.append(urllib_gssapi.HTTPSPNEGOAuthHandler())

opener = urllib.request.build_opener(*handlers)
urllib.request.install_opener(opener)
request = urllib.request.Request(url, data)
```

## Credits

Robbie Harwood ported to python-gssapi and renamed to urllib_gssapi ([this
repo!](https://github.com/pythongssapi/urllib_gssapi)).

Will Thames maintained [a fork](https://github.com/willthames/urllib_kerberos)
for a while.

Tim Olsen was the original author of `urllib2_kerberos`
[library](https://bitbucket.org/tolsen/urllib2_kerberos) which is the bulk of
the content of the `urllib_kerberos` module.
