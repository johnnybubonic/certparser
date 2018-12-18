#!/usr/bin/env python3

# stdlib
import argparse
import collections
import copy
import datetime
import hashlib
import importlib
import ipaddress
import json
import os
import pprint
import re
import shutil
import socket
import ssl
from urllib import parse
# PyPi/PIP
# These are handled automagically.
# If you'd rather install them via your distro's package manager (YOU SHOULD),
# then install them first then run this script.
# Otherwise you'll have to use pip to remove them.
thrd_prty = {'OpenSSL': 'pyOpenSSL',
             #'pyasn1': 'pyasn1',
             #'jinja2': 'Jinja2',
             'validators': 'validators'}

cols = shutil.get_terminal_size((80, 20)).columns

for mod in thrd_prty:
    try:
        globals()[mod] = importlib.import_module(mod)
    except ImportError:
        import pip
        pip.main(['install', '--quiet', '--quiet', '--quiet',
                  '--user', thrd_prty[mod]])
        globals()[mod] = importlib.import_module(mod)

class CertParse(object):
    def __init__(self, target, port = 443, force = None, cert_type = 'pem',
                 json_fmt = False, starttls = False, extensions = False,
                 alt_names = False):
        self.target = target
        self.port = port
        self.force_type = force
        self.cert_type = cert_type
        self.starttls = starttls
        self.json_fmt = json_fmt
        self.extensions = extensions
        self.alt_names = alt_names
        self.cert = None
        self.certinfo = None
        self.get_type()

    def getCert(self):
        if self.cert_type.lower() == 'pem':
            self.cert_type = OpenSSL.crypto.FILETYPE_PEM
        elif self.cert_type.lower() == 'asn1':
            self.cert_type = OpenSSL.crypto.FILETYPE_ASN1
        else:
            raise ValueError(('{0} is not a valid cert type; must be either ' +
                              '"pem" or "asn1"').format(self.cert_type))
        if not self.force_type in ('url', 'domain', 'ip'):
            with open(self.target, 'rb') as f:
                self.cert = OpenSSL.crypto.load_certificate(self.cert_type,
                                                            f.read())
        else:
            _cert = ssl.get_server_certificate((self.target, self.port))
            self.cert = OpenSSL.crypto.load_certificate(self.cert_type,
                                                        _cert)
        return()

    def parseCert(self):
        certinfo = collections.OrderedDict()
        timefmt = '%Y%m%d%H%M%SZ'
        certinfo['Subject'] = self.parse_name(self.cert.get_subject().\
                                                            get_components())
        certinfo['EXPIRED'] = self.cert.has_expired()
        certinfo['Issuer'] = self.parse_name(self.cert.get_issuer().\
                                                            get_components())
        certinfo['Issued'] = str(datetime.datetime.strptime(
                                    self.cert.get_notBefore().decode('utf-8'),
                                    timefmt))
        certinfo['Expires'] = str(datetime.datetime.strptime(
                                    self.cert.get_notAfter().decode('utf-8'),
                                    timefmt))
        if self.extensions:
            certinfo['Extensions'] = self.parse_ext()
        elif self.alt_names:
            certinfo['SANs'] = self.parse_ext_san_only()
        certinfo['Pubkey'] = self.get_pubkey()
        certinfo['Serial'] = int(self.cert.get_serial_number())
        certinfo['Signature Algorithm'] = self.cert.get_signature_algorithm().\
                                                                decode('utf-8')
        certinfo['Version'] = self.cert.get_version()
        certinfo['Subject Name Hash'] = self.cert.subject_name_hash()
        certinfo['Fingerprints'] = self.gen_hashes()
        self.certinfo = certinfo
        return()

    def print(self, json_fmt = None):
        if json_fmt is None:
            json_fmt = self.json_fmt
        if json_fmt:
            output = json.dumps(self.certinfo, indent = 4)
        else:
            output = self.certinfo
        if __name__ == '__main__':
            if not json_fmt:
                pprint.pprint(output, compact = False, width = cols)
            else:
                print(output)
            return()
        return(output)

    def get_pubkey(self):
        pubkey = {}
        key = self.cert.get_pubkey()
        pubkey['Bit Length'] = key.bits()
        # I wish there was a more comfortable way of comparing these.
        if key.type() == OpenSSL.crypto.TYPE_RSA:
            pubkey['Algorithm'] = 'RSA'
        elif key.type() == OpenSSL.crypto.TYPE_DSA:
            pubkey['Algorithm'] = 'DSA'
        return(pubkey)

    def gen_hashes(self):
        hashes = {}
        # Note: MD2 is *so old* that they aren't even
        # *supported in python 3*.
        # If we NEED to implement, https://urchin.earth.li/~twic/md2.py
        fpt_types = sorted([i.lower() for i in ['md2', 'md5', 'sha1', 'mdc2',
                                                'ripemd160', 'blake2b512',
                                                'blake2s256', 'sha224',
                                                'sha256', 'sha384', 'sha512']])
        supported_types = sorted([i.lower() for i in \
                                  list(hashlib.algorithms_available)])
        cert_hash_types = [i for i in fpt_types if i in supported_types]
        for h in cert_hash_types:
            hashes[h.upper()] = self.cert.digest(h).decode('utf-8')
        return(hashes)

    def parse_name(self, item):
        component_map = {'C': 'Country',
                         'countryName': 'Country',
                         'ST': 'State/Province',
                         'stateOrProvinceName': 'State/Province',
                         'L': 'Locality/City/Town/Region',
                         'localityName': 'Locality/City/Town/Region',
                         'O': 'Organization',
                         'organizationName': 'Organization',
                         'OU': 'Department/Team/Organization Unit',
                         'organizationalUnitName': ('Department/Team/' +
                                                    'Organization Unit'),
                         'CN': 'Common name',
                         'commonName': 'Common name',
                         'emailAddress': 'eMail Address'}
        info = {}
        for c in item:
            item = c[0].decode('utf-8')
            value = c[1].decode('utf-8')
            if item in component_map.keys():
                info[component_map[item]] = value
            else:
                info[item] = value
        return(info)

    def parse_ext_san_only(self):
        SANs = []
        for idx in range(0, self.cert.get_extension_count()):
            ext = self.cert.get_extension(idx)
            name = ext.get_short_name().decode('utf-8').lower()
            x = str(ext).strip()
            if name == 'subjectaltname':
                val_lst = [i.strip() for i in x.split(',')]
                for v in val_lst:
                    parsed_val = re.sub('^\s*DNS:\s*(.*)', '\g<1>', v)
                    if parsed_val not in ('\n', ''):
                        SANs.append(parsed_val.lower())
        return(SANs)

    def parse_ext(self):
        exts = {}
        for idx in range(0, self.cert.get_extension_count()):
            ext = self.cert.get_extension(idx)
            keyname = ext.get_short_name().decode('utf-8')
            value_str = str(ext).strip()
            # These should be split into lists by commas.
            if keyname in ('subjectAltName', 'keyUsage', 'extendedKeyUsage',
                           'basicConstraints'):
                val_lst = [i.strip() for i in value_str.split(',')]
                value_str = []
                for v in val_lst:
                    parsed_val = re.sub('^\s*DNS:\s*(.*)', '\g<1>', v)
                    if parsed_val not in ('\n', ''):
                        value_str.append(parsed_val)
            # These should be split into lists by lines.
            elif keyname in ('certificatePolicies', 'ct_precert_scts',
                             'authorityInfoAccess'):
                val_lst = [i.strip() for i in value_str.splitlines()]
                value_str = []
                for v in val_lst:
                    value_str.append(v)
            exts[keyname] = value_str
        # These are split FURTHER into dicts but require unique... massaging.
        # authorityInfoAccess
        if 'authorityInfoAccess' in exts.keys():
            _tmp = copy.deepcopy(exts['authorityInfoAccess'])
            exts['authorityInfoAccess'] = {}
            for i in _tmp:
                x = [n.strip() for n in i.split('-', 1)]
                y = [n.strip() for n in x[1].split(':', 1)]
                exts['authorityInfoAccess'][x[0]] = {y[0]: y[1]}
        # authorityKeyIdentifier
        if 'authorityKeyIdentifier' in exts.keys():
            _tmp = copy.deepcopy(exts['authorityKeyIdentifier'])
            exts['authorityKeyIdentifier'] = {_tmp.split(':', 1)[0]:
                                                        _tmp.split(':', 1)[1]}
        # basicConstraints
        if 'basicConstraints' in exts.keys():
            _tmp = copy.deepcopy(exts['basicConstraints'])
            exts['basicConstraints'] = {}
            for i in _tmp:
                x = [n.strip() for n in i.split(':', 1)]
                if len(x) >= 1:
                    if x[1].lower() in ('true', 'false'):
                        x[1] = (x[1].lower() == 'true')
                    exts['basicConstraints'][x[0]] = x[1]
                else:
                    exts['basicConstraints'][x[0]] = True
        # certificatePolicies
        # What a mess.
        if 'certificatePolicies' in exts.keys():
            _tmp = copy.deepcopy(exts['certificatePolicies'])
            exts['certificatePolicies'] = {}
            last_key = None
            for i in [n.strip() for n in _tmp]:
                l = [y for y in i.split(':', 1) if y not in ('', None)]
                if len(l) > 1:
                    # It MAY be a key:value.
                    if re.search('^\s+', l[1]):
                        val = l[1].strip()
                        if last_key == 'Policy':
                            if not isinstance(exts['certificatePolicies']\
                                                                    [last_key],
                                              list):
                                exts['certificatePolicies'][last_key] = [
                                        exts['certificatePolicies'][last_key]]
                            exts['certificatePolicies'][last_key].append(val)
                        # I can't seem to get CPS as a separate dict.
                        # Patches welcome.
                        # Also, are CPS and User Notice *subitems* of Policy
                        # items?
                        elif last_key not in ('User Notice', 'CPS'):
                            # It's a value.
                            last_key = l[0].strip()
                            exts['certificatePolicies'][last_key] = val
                        else:
                            k = l[0].strip()
                            exts['certificatePolicies'][last_key][k] = val
                else:
                    # Standalone key line
                    last_key = l[0].strip()
                    exts['certificatePolicies'][last_key] = {}
        # ct_precert_scts
        # another mess. a much. much, bigger mess.
        if 'ct_precert_scts' in exts.keys():
            _tmp = copy.deepcopy(exts['ct_precert_scts'])
            exts['ct_precert_scts'] = {}
            last_key = None
            last_sub_key = None
            cnt = 0
            for i in [n.strip() for n in _tmp]:
                l = [y for y in i.split(':', 1) if y not in ('', None)]
                if len(l) > 1:
                    # Is it a line continuation (of a hex value)?
                    if ((re.search('^[0-9A-Z]{2}$', l[0])) and
                                (re.search('^[0-9A-Z:]*:?$', ':'.join(l)))):
                        exts['ct_precert_scts'][last_key][cnt]\
                                                [last_sub_key] += ':'.join(l)
                        continue
                    # It MAY be a key:value.
                    if re.search('^\s+', l[1]) and (
                                            last_key !=
                                            'Signed Certificate Timestamp'):
                        # It's a value.
                        last_key = l[0].strip()
                        val = l[1].strip()
                        if val.lower() == 'none':
                            val = None
                        exts['ct_precert_scts'][last_key] = val
                    elif re.search('^\s+', l[1]):
                        last_sub_key = l[0].strip()
                        val = l[1].strip()
                        if val.lower() == 'none':
                            val = None
                        if last_sub_key == 'Signature':
                            val += ' '
                        exts['ct_precert_scts'][last_key][cnt]\
                                                        [last_sub_key] = val
                else:
                    # Standalone key line
                    last_key = l[0].strip()
                    if last_key == 'Signed Certificate Timestamp':
                        if last_key not in exts['ct_precert_scts'].keys():
                            exts['ct_precert_scts'][last_key] = [{}]
                        else:
                            exts['ct_precert_scts'][last_key].append({})
                            cnt += 1
            # some laaaast bit of cleanup...
            if 'Signed Certificate Timestamp' in exts['ct_precert_scts']:
                for i in exts['ct_precert_scts']\
                                            ['Signed Certificate Timestamp']:
                    if 'Signature' in i.keys():
                        d = i['Signature'].split()
                        i['Signature'] = {d[0]: d[1]}
        return(exts)

    def get_domain_from_url(self, url):
        orig_url = url
        # Needed in case a URL is passed with no http:// or https://, etc.
        url = re.sub('^((ht|f)tps?://)*',
                     'https://',
                     url,
                     re.IGNORECASE).lower()
        if not self.validURL(url):
            raise ValueError(('{0} is not a valid URL').format(orig_url))
        domain = parse.urlparse(url).netloc
        return(domain)

    def validIP(self, ip):
        is_valid = False
        try:
            ipaddress.ip_address(self.target)
            is_valid = True
        except ValueError:
            pass
        return(is_valid)

    def validDomain(self, domain):
        is_valid = False
        if not isinstance(validators.domain(domain),
                          validators.utils.ValidationFailure):
            is_valid = True
        return(is_valid)

    def validURL(self, url):
        is_valid = False
        if not isinstance(validators.url(url),
                          validators.utils.ValidationFailure):
            is_valid = True
        return(is_valid)

    def validPath(self, path):
        is_valid = False
        if os.path.isfile(path):
            is_valid = True
        return(is_valid)

    def get_type(self):
        if self.force_type:
            # Just run the validator and some cleanup.
            if self.force_type == 'url':
                self.target = self.get_domain_from_url(self.target)
                chk = self.validURL(self.target)
                if chk:
                    self.force_type = 'domain'
            elif self.force_type == 'ip':
                chk = self.validIP(self.target)
            elif self.force_type == 'domain':
                chk = self.validDomain(self.target)
            elif self.force_type == 'file':
                self.target = os.path.abspath(os.path.expanduser(self.target))
                chk = self.validPath(self.target)
            if not chk:
                raise TypeError(('{0} does not appear to be a valid ' +
                                 'instance of type {1}'.format(self.target,
                                                               self.force_type)
                                ))
            if self.force_type in ('url', 'domain', 'ip'):
                self.remote = True
            else:
                self.remote = False
            return()
        # Is it an IP address?
        if self.validIP(self.target):
            self.force_type = 'ip'
            return()
        # Is it a filepath?
        fpath = os.path.abspath(os.path.expanduser(self.target))
        if self.validPath(fpath):
            self.target = fpath
            self.force_type = 'file'
            return()
        # Is it a domain?
        if self.validDomain(self.target):
            self.force_type = 'domain'
            return()
        # Lastly, is it a URL?
        if self.validURL(self.target):
            domain = self.get_domain_from_url(self.target)
            if self.validDomain(domain):
                self.target = domain
                self.force_type = 'domain'
        if not self.force_type:  # We couldn't detect it
            raise RuntimeError(('Automatic type detection of {0} requested ' +
                                'but we could not determine what type of ' +
                                'resource it is'))
        return()

def parseArgs():
    args = argparse.ArgumentParser()
    args.add_argument('-e', '--extensions',
                      dest = 'extensions',
                      action = 'store_true',
                      help = ('If specified, include ALL extension info ' +
                              '(this DRASTICALLY increases the output. You ' +
                              'have been warned)'))
    args.add_argument('-a', '--alt-names',
                      dest = 'alt_names',
                      action = 'store_true',
                      help = ('If specified, ONLY include the SAN (Subject ' +
                              'Alt Name) extension. This is highly ' +
                              'recommended over -e/--extensions. Ignored if ' +
                              '-e/--extensions is set (as the SANs are ' +
                              'included in that)'))
    args.add_argument('-j','--json',
                      dest = 'json_fmt',
                      action = 'store_true',
                      help = ('If specified, return the results in JSON'))
    args.add_argument('-f', '--force',
                      choices = ['url', 'domain', 'ip', 'file'],
                      default = None,
                      help = ('If specified, force the TARGET to be parsed ' +
                              'as the given type'))
    args.add_argument('-p', '--port',
                      dest = 'port',
                      type = int,
                      default = 443,
                      help = ('Use a port other than 443 (only used for ' +
                              'URL/domain/IP address targets)'))
    args.add_argument('-t', '--cert-type',
                      dest = 'cert_type',
                      default = 'pem',
                      choices = ['pem', 'asn1'],
                      help = ('The type of certificate (only used for '
                              'file targets). Note that "DER"-encoded ' +
                              'certificates should use "asn1". The default ' +
                              'is pem'))
#    TODO: I think the starttls process depends on the protocol? If so, this...
#          won't be feasible.
#    args.add_argument('-s', '--starttls',
#                      dest = 'starttls',
#                      action = 'store_true',
#                      help = ('If specified, initiate STARTTLS on the ' +
#                              'target instead of pure SSL/TLS'))
    args.add_argument('TARGET',
                      help = ('The target to gather cert info for. Can be a ' +
                              'filepath (to the certificate, not key etc.), ' +
                              'a URL/domain, or IP address'))
    return(args)

def main():
    args = vars(parseArgs().parse_args())
    args['target'] = copy.deepcopy(args['TARGET'])
    del(args['TARGET'])
    p = CertParse(**args)
    p.getCert()
    p.parseCert()
    p.print()

if __name__ == '__main__':
    main()
