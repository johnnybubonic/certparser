# Certparser


## What is it?
Certparser is a fairly small module that will parse an X.509 certificate. These are commonly referred to as "HTTPS certificates", "SSL certificates" (even though proper modern implementations should be using TLS),  etc.

Certparser can operate on either a local file (or input stream, etc.) or remote (across a small subset of protocols which will expand with time).

X.509 is a complex thing, so if I missed part of it please [let me know](https://bugs.square-r00t.net/index.php?project=12)! (RFC numbers and sections *very* welcome.)


## Quickstart
It can be invoked directly as a command:

```bash
./certparser.py 
```

(See `./certparser.py --help` for more information on usage.)

Or as a python module:

```python
import certparser

parser = certparser.CertParse('square-r00t.net')
print(parser.cert)      # prints the fetched certificate
print(parser.certinfo)  # prints the parsed certificate information
```

(See `pydoc certparser` for more information on usage.)


## Requirements
Currently, only the following non-stdlib modules are required:

* [pyOpenSSL](https://pyopenssl.org/en/stable/)
* [validators](https://validators.readthedocs.io/en/latest/)

As parsing work continues and features/protocols are added, the following will **probably** be used (but are NOT currently):

* [pyasn1](https://github.com/etingof/pyasn1)
* [jinja2](http://jinja.pocoo.org/)

And the following will be required optionally (but recommended):

* [lxml](https://lxml.de/)
