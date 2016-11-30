# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import hashlib


class IssueManager:

    def __init__(self):
        self.SSLYZE_ISSUES = {
            "Client-initiated Renegotiations": {
                "Summary": "Client-initiated Renegotiations - Honored",
                "Severity": "Medium",
                "Description": "Test the server for client-initiated renegotiation support",
                "Classification": {
                    "cwe_id": "310",
                    "cwe_url": "http://cwe.mitre.org/data/definitions/310.html"
                },
                "issue_type": "configuration"
            },
            "Secure Renegotiation":  {
                "Summary": "Secure Renegotiation - Not supported",
                "Severity": "Medium",
                "Description": "Test the server for secure renegotiation support",
                "Classification": {
                    "cwe_id": "310",
                    "cwe_url": "http://cwe.mitre.org/data/definitions/310.html"
                },
                "issue_type": "configuration"
            },
            "Compression": {
                "Summary": "Compression - Supported",
                "Severity": "High",
                "Description": "Test the server for Zlib compression support",
                "Classification": {
                    "cwe_id": "310",
                    "cwe_url": "http://cwe.mitre.org/data/definitions/310.html"
                },
                "issue_type": "configuration",
                "handler": self.handler_compression_issue
            },
            "Heartbleed": {
                "Summary": "Heartbleed vulnerable",
                "Severity": "High",
                "Description": "Vulnerable with the OpenSSL Heartbleed vulnerability",
                "Classification": {
                    "cwe_id": "126",
                    "cwe_url": "http://cwe.mitre.org/data/definitions/126.html"
                },
                "issue_type": "configuration"
            },
            "Session resumption with session IDs": {
                "Summary": "Session resumption with session IDs - Not supported",
                "Severity": "Info",
                "Description": "Test the server for session resumption support using session IDs",
                "issue_type": "configuration"
            },
            "Session resumption with TLS session tickets": {
                "Summary": "Session resumption with TLS session tickets - Not supported",
                "Severity": "Info",
                "Description": "Test the server for session resumption support using TLS session tickets",
                "issue_type": "configuration"
            },
            "HSTS": {
                "Summary": "No HTTP Strict Transport Security (HSTS) directive",
                "Severity": "Info",
                "Description": "HSTS is a web security policy mechanism which is necessary to protect secure "
                               "HTTPS websites against downgrade attacks, and which greatly simplifies protection "
                               "against cookie hijacking. It allows web servers to declare that web browsers "
                               "(or other complying user agents) should only interact with it using secure "
                               "HTTPS connections, and never via the insecure HTTP protocol",
                "issue_type": "configuration"
            },
            "Public key size": {
                "Summary": "Public key size lower than 2048 bits",
                "Severity": "High",
                "Description": "Verify that the the public key size is not lower than 2048 bits",
                "Classification": {
                    "cwe_id": "320",
                    "cwe_url": "http://cwe.mitre.org/data/definitions/320.html"
                },
                "issue_type": "certificate",
                "handler": self.handler_low_key_size
            },
            "Expired Validity date": {
                "Summary": "Certificate expired: Validity date before current date",
                "Severity": "High",
                "Description": "Verify that the validity date of the certificate is not before the current date",
                "Classification": {
                    "cwe_id": "324",
                    "cwe_url": "http://cwe.mitre.org/data/definitions/324.html"
                },
                "issue_type": "certificate",
                "handler": self.handler_certificate_expired
            },
            "Before Validity date": {
                "Summary": "Certificate not valid: Validity date starts after current date",
                "Severity": "High",
                "Description": "The validity of the certificate is after the current date",
                "Classification": {
                    "cwe_id": "324",
                    "cwe_url": "http://cwe.mitre.org/data/definitions/324.html"
                },
                "issue_type": "certificate",
                "handler": self.handler_certificate_not_valid_yet
            },
            "Hostname validation": {
                "Summary": "Hostname Validation - NOT OK",
                "Severity": "High",
                "Description": "Verify if the common name matches",
                "Classification": {
                    "cwe_id": "297",
                    "cwe_url": "http://cwe.mitre.org/data/definitions/297.html"
                },
                "issue_type": "hostname",
                "handler": self.handler_hostname_validation
            },
            "Certificate validation": {
                "Summary": "Certificate validation - NOT OK",
                "Severity": "High",
                "Description": "Verify the validity of the server certificate against various trusts stores",
                "Classification": {
                    "cwe_id": "295",
                    "cwe_url": "http://cwe.mitre.org/data/definitions/295.html"
                },
                "issue_type": "certificate",
                "handler": self.handler_certificate_not_valid
            },
            "SSLv2": {
                "Summary": "SSL 2.0 - List of accepted cipher suites not empty",
                "Severity": "High",
                "Description": "The SSL 2.0 OpenSSL cipher suites supported by the server is not empty",
                "Classification": {
                    "cwe_id": "327",
                    "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
                },
                "issue_type": "configuration",
                "handler": self.handler_ssl_supported
            },
            "SSLv3": {
                "Summary": "SSL 3.0 -  List of accepted cipher suites not empty",
                "Severity": "High",
                "Description": "The SSL 3.0 OpenSSL cipher suites supported by the server is not empty",
                "Classification": {
                    "cwe_id": "327",
                    "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
                },
                "issue_type": "configuration",
                "handler": self.handler_ssl_supported
            },
            "no_tls_v1_2": {
                "Summary": "TLS 1.2 - Not supported",
                "Severity": "Medium",
                "Description": "TLS 1.2 is not supported by this server",
                "Classification": {
                    "cwe_id": "327",
                    "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
                },
                "issue_type": "configuration"
            },
            "blacklisted": {
                "Summary": "List of accepted cipher suites contains blacklisted encryption cipher suites",
                "Severity": "High",
                "Description": "The OpenSSL cipher suites supported by the server contains "
                               "blacklisted encryption cipher suites which are not secure at all",
                "Classification": {
                    "cwe_id": "327",
                    "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
                },
                "issue_type": "configuration",
                "handler": self.handler_bad_cipher
            },
            "unauthorized": {
                "Summary": "List of accepted cipher suites contains unauthorized encryption cipher suites",
                "Severity": "Medium",
                "Description": "The OpenSSL cipher suites supported by the server contains "
                               "non authorized encryption cipher suites which are not secure",
                "Classification": {
                    "cwe_id": "327",
                    "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
                },
                "issue_type": "configuration",
                "handler": self.handler_bad_cipher
            },
            "no_order": {
                "Summary": "List of accepted cipher suites is not in the correct order",
                "Severity": "Medium",
                "Description": "The OpenSSL cipher suites supported by the server is order enforced "
                               "regarding the existing white-list.",
                "Classification": {
                    "cwe_id": "327",
                    "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
                },
                "issue_type": "configuration",
                "handler": self.handler_no_cipher_order
            },
            "deprecated": {
                "Summary": "List of accepted cipher suites contains deprecated cipher",
                "Severity": "Low",
                "Description": "The OpenSSL cipher suites supported by the server contains deprecated cipher "
                               "that need to be removed in the future",
                "Classification": {
                    "cwe_id": "327",
                    "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
                },
                "issue_type": "configuration",
                "handler": self.handler_bad_cipher
            },
            "wrong_wildcard": {
                "Summary": "Incorrect usage of wildcard for CommonName or AlternativeName",
                "Severity": "Low",
                "Description": "The wildcard in the CommonName or AlternativeName is used incorrectly."
                               " The domain mustn't contains a wildcard '*' within its name",
                "Classification": {
                    "cwe_id": "327",
                    "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
                },
                "issue_type": "configuration",
                "handler": self.handler_wildcard_issue
            },
            "domain_wildcard": {
                "Summary": "Dangerous usage of wildcard for CommonName or AlternativeName",
                "Severity": "Low",
                "Description": "The wildcard in the CommonName or AlternativeName is used incorrectly."
                               " The wildcard '*' used as a sub-domain is too close to the top domain",
                "Classification": {
                    "cwe_id": "327",
                    "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
                },
                "issue_type": "configuration",
                "handler": self.handler_wildcard_issue
            },
            "no_ca": {
                "Summary": "No certificate verification",
                "Severity": "Info",
                "Description": "The certificate for the host has not been checked"
            },
            "get_no_ca": {
                "Summary": "Could not enforce certificate verification",
                "Severity": "Error",
                "Description": "SSlyze could not retreive the certificate of the server during the analysis. ",
                "handler": self.handler_certificate_not_found
            },
            "extra_cert": {
                "Summary": "Extra certificate in the chain",
                "Severity": "Info",
                "Description": "Those seem to be bugs in NSS validation which cause the library it to prefer "
                               "lower security validation paths using older certificates "
                               "over higher security validation paths using newer certificates.",
                "Classification": {
                    "cwe_id": "327",
                    "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
                },
                "issue_type": "configuration"
            },
            "no_ocsp": {
                "Summary": "No OCSP Stapling provided",
                "Severity": "Info",
                "Description": "The server does not provides OCSP Stapling for its certificate. "
                               "OCSP Stapling is used for checking the revocation status of existing certificate "
                               "in order to quicken the TLS hand-check",
                "issue_type": "configuration"
            },
            "chain_order": {
                "Summary": "The chain certificate is not in the correct order",
                "Severity": "Medium",
                "Description":  "The certificate chain sent by the server is in an incorrect order. "
                                "This could affects browsers with limited resources like smartphones.",
                "Classification": {
                    "cwe_id": "327",
                    "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
                },
                "issue_type": "configuration"
            },
            "sha1_leaf_cert": {
                "Summary": "Certificate signed with SHA-1",
                "Severity": "High",
                "Description":  "The certificate for this domain is signed with SHA-1. This signature algorithm "
                                "is deprecated and will be forbidden in 2017. "
                                "You need to update your certificate with a better signature algorithm like SHA-2 "
                                "because soon browsers won't allow it.",
                "Classification": {
                    "cwe_id": "327",
                    "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
                },
                "issue_type": "certificate"
            },
            "no_ats": {
                "Summary": "Domain not compatible with ATS",
                "Severity": "High",
                "Description":  "The domain doesn't comply with Apple App Transport Security requirements "
                                "on the following points :"
                                ,
                "Classification": {
                    "cwe_id": "327",
                    "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
                },
                "issue_type": "configuration",
                "handler": self.handler_ats_not_valid
            }
        }

    # Keep track of targets
    """
    targets = {
        'target_1': {
            'issue_1':  [{'sample': 'sample_1', 'evidence': 'proof'},
                         {'sample': 'sample_2', 'evidence': 'proof_2'}],
            'issue_2':  [(value_1, value_2)],
            'infos':    {'info_1': 'value', 'info_2': 'value 2'}
        }
    }
    """
    targets = {}
    current_target = None

    # Get reference to current target dict blob
    def get_target(self, name=None):
        if not name:
            # Check if the current target is defined
            if not self.current_target:
                self.new_target()

            name = self.current_target

        return self.targets.get(name)

    # Set current target, create new one if doesn't exist
    def set_target(self, name):
        # Check if name exists
        if name not in self.targets:
            self.new_target(name)
        else:
            self.current_target = name

    def new_target(self, name=None):
        # Check if the name if defined
        if not name:
            name = "target_%d" % (len(self.targets) + 1)

        self.current_target = name

        self.targets[self.current_target] = {}

    def add_target_info(self, infos, name=None):
        """
        :param infos: {key: value}
        :type infos: dict
        :param name: name of the target, if None will use current target
        """
        target = self.get_target(name)

        # Initialize field
        if 'infos' not in target:
            target["infos"] = dict()

        target_infos = target.get('infos')

        target_infos.update(infos)

    def add_issues(self, issue_title, content, target=None):
        # Get current issues
        issues = self.get_target(target)

        # Initialize field
        if issue_title not in issues:
            issues[issue_title] = list()

        issue = issues.get(issue_title)

        issue.append(content)

    # SSL v2 is supported
    def support_sslv2(self, preferred_cipher, accepted_ciphers, target=None):
        self.add_issues("SSLv2", (preferred_cipher, accepted_ciphers), target)

    # SSL v3 is supported
    def support_sslv3(self, preferred_cipher, accepted_ciphers, target=None):
        self.add_issues("SSLv3", (preferred_cipher, accepted_ciphers), target)

    def handler_ssl_supported(self, content):
        # extract content
        content = content[0]

        # Format parameters
        (preferred_cipher, accepted_ciphers) = content

        precisions = dict()
        precisions["Extra"] = "Preferred Cipher: %s<br/>" % preferred_cipher[0]
        precisions["Extra"] += "Accepted Ciphers: %s" % ", ".join(accepted_ciphers)

        return precisions

    # TLS v1.2 is not supported
    def no_tls_v1_2(self, target=None):
        self.add_issues("no_tls_v1_2", None, target)

    # Create blacklisted cipher issue
    def blacklisted_cipher(self, version, ciphers, target=None):
        self.add_issues("blacklisted", {version: ciphers}, target)

    # Create unauthorized cipher issue (not in whitelist, but not in blacklist)
    def unauthorized_cipher(self, version, ciphers, target=None):
        self.add_issues("unauthorized", {version: ciphers}, target)

    # Create deprecated cipher issue (cipher in deprecated list)
    def deprecated_cipher(self, version, ciphers, target=None):
        self.add_issues("deprecated", {version: ciphers}, target)

    def handler_bad_cipher(self, content):
        precisions = dict()
        precisions["Extra"] = ""

        # Get every instance of the issue
        for item in content:
            for version in item:
                precisions["Extra"] += "With %s : %s<br/>" % (version, item[version])

        return precisions

    # Create no Honor Cipher Order issue (preferred cipher is not the safer one from available)
    def no_cipher_order(self, version, safer_cipher, preferred_cipher, target=None):
        self.add_issues("no_order", {version: (safer_cipher, preferred_cipher)}, target)

    def handler_no_cipher_order(self, content):
        precisions = dict()
        precisions["Extra"] = ""

        # Get every instance of the issue
        for item in content:
            for version in item:
                (safer_cipher, preferred_cipher) = item[version]
                precisions["Extra"] += "With %s : %s should be preferred instead of current %s<br/>" % \
                                       (version, safer_cipher, preferred_cipher)

        return precisions

    # Create wrong wildcard usage issue ( *sub.domain.tld is considered dangerous)
    def wrong_wildcard(self, domains, target=None):
        self.add_issues("wrong_wildcard", domains, target)

    # Create domains wildcard issue (wildcard is used too close to top domain)
    def domain_wildcard(self, domains, target=None):
        self.add_issues("domain_wildcard", domains, target)

    def handler_wildcard_issue(self, content):
        # extract content
        content = content[0]

        precisions = dict()
        precisions["Extra"] = "Wildcard issue with following domains:<br/>"

        for domain in content:
            precisions["Extra"] += "%s<br/>" % domain

        return precisions

    def client_renegotiation(self, target=None):
        self.add_issues("Client-initiated Renegotiations", None, target)

    def secure_renegotiation(self, target=None):
        self.add_issues("Secure Renegotiation", None, target)

    def insecure_compression(self, compressions, target=None):
        self.add_issues("Compression", compressions, target)

    def handler_compression_issue(self, content):
        # extract content
        content = content[0]

        precisions = dict()
        precisions["Extra"] = "Compression available with following methods:<br/>"

        for method in content:
            precisions["Extra"] += "%s<br/>" % method

        return precisions

    def heartbleed(self, target=None):
        self.add_issues("Heartbleed", None, target)

    def no_hsts(self, target=None):
        self.add_issues("HSTS", None, target)

    def session_resumption_id(self, target=None):
        self.add_issues("Session resumption with session IDs", None, target)

    def session_resumption_ticket(self, target=None):
        self.add_issues("Session resumption with TLS session tickets", None, target)

    def no_ocsp_stapling(self, target=None):
        self.add_issues("no_ocsp", None, target)

    # Public key for certificate is too small
    def low_key_size(self, min_size, current_size, target=None):
        self.add_issues("Public key size", (min_size, current_size), target)

    def handler_low_key_size(self, content):
        # extract content
        content = content[0]

        # Format parameters
        (min_size, current_size) = content

        precisions = dict()
        precisions["Evidence"] = "Size of the public key: %s bits that is lower to minimum of %s bits" \
                                 % (current_size, min_size)
        return precisions

    # Certificate validity date is expired
    def certificate_expired(self, validity_date, current_date, target=None):
        self.add_issues("Expired Validity date", (validity_date, current_date), target)

    def handler_certificate_expired(self, content):
        # extract content
        content = content[0]

        # Format parameters
        (validity_date, current_date) = content

        precisions = dict()
        precisions["Evidence"] = "The certificate is valid only until %s and have been observed on %s" \
                                 % (validity_date, current_date)
        return precisions

    # Certificate validity date is not yet
    def certificate_not_valid_yet(self, validity_date, current_date, target=None):
        self.add_issues("Before Validity date", (validity_date, current_date), target)

    def handler_certificate_not_valid_yet(self, content):
        # extract content
        content = content[0]

        # Format parameters
        (validity_date, current_date) = content

        precisions = dict()
        precisions["Evidence"] = "The certificate is valid only after %s and have been observed on %s" \
                                 % (validity_date, current_date)
        return precisions

    # Hostname doesn't match certificate
    def no_hostname_validation(self, hostname, valid_names, target=None):
        self.add_issues("Hostname validation", (hostname, valid_names), target)

    def handler_hostname_validation(self, content):
        # extract content
        content = content[0]

        # Format parameters
        (hostname, valid_names) = content

        precisions = dict()
        precisions["Extra"] = "The hostname is %s but the certificate is valid only with the following domains:<br/>" \
                              % hostname

        # Remove duplicate
        for name in set(valid_names):
            precisions["Extra"] += "\t%s<br/>" % name

        return precisions

    # Extra certificate in the validation path
    def extra_cert(self, target=None):
        self.add_issues("extra_cert", None, target)

    # Certificate not valid for CA
    def certificate_not_valid(self, cert_error, target=None):
        self.add_issues("Certificate validation", cert_error, target)

    def handler_certificate_not_valid(self, content):
        # extract content
        content = content[0]

        # Format parameters
        cert_error = content

        precisions = dict()
        precisions["Extra"] = "Bad certificate validation for the following store(s): <br/> %s" % cert_error

        return precisions

    # Could not get the certificate info
    def certificate_not_found(self, error, target=None):
        self.add_issues("get_no_ca", error, target)

    def handler_certificate_not_found(self, content):
        # extract content
        content = content[0]

        # Format parameters
        cert_error = content

        precisions = dict()
        precisions["Evidence"] = cert_error

        return precisions

    def handler_ats_not_valid(self, content):
        precisions = dict()
        precisions["Extra"] = ""

        # extract content
        for item in content:
            key = item.keys()[0]

            if key == "support_tls_v1_2":
                precisions["Extra"] += "TLS v1.2 is not supported <br/>"

            elif key in ["pub_key_size", "pub_key_algo"]:
                # {"pub_key_size": str(key_size), "pub_key_algo": "ECDSA"}
                precisions["Extra"] += "The size of the {algo} public key is too small: {size} bits <br/>"\
                    .format(algo=item.get("pub_key_algo"), size=item.get("pub_key_size"))

            elif key == "support_fs":
                precisions["Extra"] += "None of the ciphers proposed for TLS v1.2 supports Perfect Forward Secrecy<br/>"
            elif key == "sha1":
                precisions["Extra"] += "The certificate is signed with SHA-1<br/>"

        return precisions

    # Certificate not checked
    def certificate_not_checked(self, target=None):
        self.add_issues("no_ca", None, target)

    # Certificate chain in incorrect order
    def wrong_chain_order(self, target=None):
        self.add_issues("chain_order", None, target)

    # Certificate chain in incorrect order
    def signed_with_sha1(self, target=None):
        self.add_issues("sha1_leaf_cert", None, target)

    def no_ats_valid(self, items, target=None):
        self.add_issues("no_ats", items, target)

    # Fill issue
    def fill_issue_with_info(self, issue, content, target_info):
        # Initialize field
        if "URLs" not in issue:
            issue["URLs"] = list()

        issue_urls = issue.get("URLs")

        # Get a local copy of the target information
        entry = target_info.copy()

        # Set url name
        entry["URL"] += " - %s" % entry.get("IP")

        # Get issue handler if the issue needs to be completed
        handler = issue.get("handler")

        # Fill issue with details
        if handler:
            precisions = handler(content)
            entry.update(precisions)

        # Add result to issue
        issue_urls.append(entry)

    # From issues found, generate issues in minion syntax
    def generate_issues(self, aggregate_issues=True):
        full_issues = {}

        # Browse each target
        for target_name in self.targets:
            target = self.targets[target_name]
            # Get target information
            target_info = target.get("infos")

            # Browse each issue
            for issue_name in target:
                # Skip information
                if issue_name == "infos":
                    continue

                if aggregate_issues:
                    issue = self.SSLYZE_ISSUES[issue_name]
                else:
                    issue = self.SSLYZE_ISSUES[issue_name].copy()

                # Add details to issue
                issue_content = target.get(issue_name)
                self.fill_issue_with_info(issue, issue_content, target_info)

                # Check if first instance of the issue
                if issue_name not in full_issues:
                    full_issues[issue_name] = [issue]

                # Store issue if no aggregation needed
                elif not aggregate_issues:
                    full_issues[issue_name].append(issue)

                # Else link to the issue is already stored

        issues = []

        # Produce minion compatible output
        for issue_name in full_issues:
            issue_instances = full_issues.get(issue_name)

            for issue in issue_instances:
                # Compute id of every issue
                self.compute_id(issue)

                # Remove handler
                if "handler" in issue:
                    issue.pop("handler")

                issues.append(issue)

        return issues

    def compute_id(self, issue):
        # Compute the id of issue
        summary = issue["Summary"] if ("Summary" in issue) else ""
        cwe_id = issue["Classification"]["cwe_id"] \
            if "Classification" in issue and "cwe_id" in issue["Classification"] else ""
        pre_id = None

        # FIXME if two scans of two targets raise an issue about the same certificate, the extra info will be
        # overwritten by the last result
        # maybe this will be fixed by a change in data model
        # Disclaimers : I know it's bad to keep commented code in source version project, but I won't forget it
        """
        # Treat case issue is dependent to certificate
        if issue.get('issue_type') == "certificate":
            try:
                cert_hash = issue.get("URLs")[0].get("CA")
            except:
                cert_hash = ""

            pre_id = summary + ":" + str(cwe_id) + ":" + cert_hash
        elif issue.get('issue_type') == 'configuration':
            try:
                # Get the url of target and ignore the IP
                target = issue.get("URLs")[0].get("URL").split(" - ")[0]
            except:
                target = ""

            pre_id = summary + ":" + str(cwe_id) + ":" + target
        """
        # Treat case issue is dependent to certificate
        if issue.get('issue_type') == "certificate":
            try:
                cert_hash = issue.get("URLs")[0].get("CA")
            except:
                cert_hash = ""
        else:
            cert_hash = ""

        try:
            # Get the url of target and ignore the IP
            target = issue.get("URLs")[0].get("URL").split(" - ")[0]
        except:
            target = ""

        pre_id = summary + ":" + str(cwe_id) + ":" + target + ":" + cert_hash

        # Compute the id
        if pre_id:
            hash_id = hashlib.sha256(pre_id.encode())
            issue['Id'] = hash_id.hexdigest()

