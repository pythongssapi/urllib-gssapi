# urllib_kerberos

## Usage

### Python 2

```
import urllib2
import urllib_kerberos

handlers.append(urllib_kerberos.HTTPKerberosAuthHandler())

opener = urllib2.build_opener(*handlers)
urllib2.install_opener(opener)
request = urllib2.Request(url, data)
```

### Python 3

```
import urllib.request
import urllib_kerberos

handlers.append(urllib_kerberos.HTTPKerberosAuthHandler())

opener = urllib.request.build_opener(*handlers)
urllib.request.install_opener(opener)
request = urllib.request.Request(url, data)
```

## Credits

Tim Olsen was the original author of `urllib2_kerberos` 
[library](https://bitbucket.org/tolsen/urllib2_kerberos)
which is the bulk of the content of the `urllib_kerberos`
module.
