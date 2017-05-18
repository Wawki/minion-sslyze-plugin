# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import unittest

from scanner import Scanner


class TestScanner(unittest.TestCase):
    configuration = {
        "blacklist_cipher": "NULL:NULL:EXPORT:_DES:MD5:PSK:annon:RC4",
        "deprecated": "3DES",
        "enforce_order": True,
        "forward_sec_cipher": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "whitelist_cipher": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_256_GCM_SHA384:TLS_RSA_WITH_AES_128_CBC_SHA256:TLS_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_CBC_SHA",
    }

    def test_cert_info_plugin(self):
        # TODO build cases based on test file from sslyze
        """
        scan = Scanner(["mozilla-modern.badssl.com"])
        scan.check_certinfo()
        scan.run()

        # scanner should raise no issue
        self.assertEqual(scan.generate_issues(), [])

        
        # FIXME find a way to test revoked certificate
        scan = Scanner(["revoked.badssl.com"])
        scan.check_certinfo()
        scan.run()
        

        scan = Scanner(["incomplete-chain.badssl.com"])
        scan.define_willdcard_level(1)
        with open("/home/glestel/effective_tld_names.dat.txt") as tld_file:
            scan.set_tld_list([line.strip() for line in tld_file if line[0] not in "/\n"])
        
        """
        scan = Scanner(["perdu.com"])
        scan.set_blacklisted_ciphers(self.configuration["blacklist_cipher"].split(':'))
        scan.set_whitelisted_ciphers(self.configuration["whitelist_cipher"].split(':'))
        scan.set_forward_sec_ciphers(self.configuration["forward_sec_cipher"].split(':'))
        scan.define_enforced_order(self.configuration["enforce_order"])
        scan.set_deprecated_ciphers(self.configuration["deprecated"].split(':'))

        #scan.set_host_resolution(True)

        scan.check_ssl_v2()
        scan.check_tls_v12()
        scan.check_certinfo()

        scan.run()
        for i in scan.generate_issues():
            print i

    if __name__ == '__main__':
        unittest.main()