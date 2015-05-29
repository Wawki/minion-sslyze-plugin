# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


import time
import os
import xml.etree.cElementTree as ET
import datetime
import uuid
import socket
from urlparse import urlparse
from minion.plugins.base import ExternalProcessPlugin

SSLYZE_ISSUES = {
    "Client-initiated Renegotiations": {
        "Summary": "Client-initiated Renegotiations - Honored",
        "Severity": "Medium",
        "Description": "Test the server for client-initiated renegotiation support",
        "Classification": {
            "cwe_id": "310",
            "cwe_url": "http://cwe.mitre.org/data/definitions/310.html"
        }
    },
    "Secure Renegotiation":  {
        "Summary": "Secure Renegotiation - Not supported",
        "Severity": "Medium",
        "Description": "Test the server for secure renegotiation support",
        "Classification": {
            "cwe_id": "310",
            "cwe_url": "http://cwe.mitre.org/data/definitions/310.html"
        }
    },
    "Compression": {
        "Summary": "Compression - Supported",
        "Severity": "High",
        "Description": "Test the server for Zlib compression support",
        "Classification": {
            "cwe_id": "310",
            "cwe_url": "http://cwe.mitre.org/data/definitions/310.html"
        }
    },
    "Heartbleed": {
        "Summary": "Heartbleed vulnerable",
        "Severity": "High",
        "Description": "Vulnerable with the OpenSSL Heartbleed vulnerability",
        "Classification": {
            "cwe_id": "126",
            "cwe_url": "http://cwe.mitre.org/data/definitions/126.html"
        }
    },
    "Session ressumption with session IDs": {
        "Summary": "Session ressumption with session IDs - Not supported",
        "Severity": "Info",
        "Description": "Test the server for session ressumption support using session IDs",
    },
    "Session ressumption with TLS session tickets": {
        "Summary": "Session ressumption with TLS session tickets - Not supported",
        "Severity": "Info",
        "Description": "Test the server for session ressumption support using TLS session tickets"
    },
    "HSTS": {
        "Summary": "No HTTP Strict Transport Security (HSTS) directive",
        "Severity": "Info",
        "Description": "HSTS is a web security policy mechanism which is necessary to protect secure HTTPS websites "
                       "against downgrade attacks, and which greatly simplifies protection against cookie hijacking. "
                       "It allows web servers to declare that web browsers (or other complying user agents) should only"
                       " interact with it using secure HTTPS connections, and never via the insecure HTTP protocol"
    },
    "Public key size": {
        "Summary": "Public key size lower than 2048 bits",
        "Severity": "High",
        "Description": "Verify that the the public key size is not lower than 2048 bits",
        "Classification": {
            "cwe_id": "320",
            "cwe_url": "http://cwe.mitre.org/data/definitions/320.html"
        }
    },
    "Expired Validity date": {
        "Summary": "Certificate expired: Validity date before current date",
        "Severity": "High",
        "Description": "Verify that the validity date of the certificate is not before the current date",
        "Classification": {
            "cwe_id": "324",
            "cwe_url": "http://cwe.mitre.org/data/definitions/324.html"
        }
    },
    "Before Validity date": {
        "Summary": "Certificate not valid: Validity date starts after current date",
        "Severity": "High",
        "Description": "The validity of the certificate is after the current date",
        "Classification": {
            "cwe_id": "324",
            "cwe_url": "http://cwe.mitre.org/data/definitions/324.html"
        }
    },
    "Hostname validation": {
        "Summary": "Hostname Validation - NOT OK",
        "Severity": "High",
        "Description": "Verify if the common name matches",
        "Classification": {
            "cwe_id": "297",
            "cwe_url": "http://cwe.mitre.org/data/definitions/297.html"
        }
    },
    "Certificate validation": {
        "Summary": "Certificate validation - NOT OK",
        "Severity": "High",
        "Description": "Verify the validity of the server certificate against various trusts stores",
        "Classification": {
            "cwe_id": "295",
            "cwe_url": "http://cwe.mitre.org/data/definitions/295.html"
        }
    },
    "SSLV2": {
        "Summary": "SSL 2.0 - List of accepted cipher suites not empty",
        "Severity": "High",
        "Description": "The SSL 2.0 OpenSSL cipher suites supported by the server is not empty",
        "Classification": {
            "cwe_id": "327",
            "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
        }
    },
    "SSLV3_notempty": {
        "Summary": "SSL 3.0 -  List of accepted cipher suites not empty",
        "Severity": "High",
        "Description": "The SSL 3.0 OpenSSL cipher suites supported by the server is not empty",
        "Classification": {
            "cwe_id": "327",
            "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
        }
    },
    "TLSV1_2_not_supported": {
        "Summary": "TLS 1.2 - Not supported",
        "Severity": "High",
        "Description": "TLS 1.2 is not supported by this server",
        "Classification": {
            "cwe_id": "327",
            "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
        }
    },
    "blacklisted": {
        "Summary": "List of accepted cipher suites contains blacklisted encryption cipher suites",
        "Severity": "High",
        "Description": "The OpenSSL cipher suites supported by the server contains "
                       "blacklisted encryption cipher suites which are not secure at all",
        "Classification": {
            "cwe_id": "327",
            "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
        }
    },
    "unauthorized": {
        "Summary": "List of accepted cipher suites contains unauthorized encryption cipher suites",
        "Severity": "Medium",
        "Description": "The OpenSSL cipher suites supported by the server contains "
                       "non authorized encryption cipher suites which are not secure",
        "Classification": {
            "cwe_id": "327",
            "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
        }
    },
    "no_order": {
        "Summary": "List of accepted cipher suites is not in the correct order",
        "Severity": "Medium",
        "Description": "The OpenSSL cipher suites supported by the server is order enforced "
                       "regarding the existing white-list.",
        "Classification": {
            "cwe_id": "327",
            "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
        }
    },
    "deprecated": {
        "Summary": "List of accepted cipher suites contains deprecated cipher",
        "Severity": "Low",
        "Description": "The OpenSSL cipher suites supported by the server contains deprecated cipher "
                       "that need to be removed in the future",
        "Classification": {
            "cwe_id": "327",
            "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
        }
    },
}


class SSLyzePlugin(ExternalProcessPlugin):
    PLUGIN_NAME = "SSlyze"
    PLUGIN_VERSION = "0.1"
    PLUGIN_WEIGHT = "light"

    SSLyze_NAME = "sslyze.py"

    # Browse accepted ciphers and check whether they are blacklisted or whitelisted
    # param:
    #   root_node :      xml element containing ciphers for a ssl/tls version
    #   version :   name of the version assessed like "tls V1.2"
    def filter_cipher(self, root_node, version):
        issues = []
        blacklisted = ""
        not_whitelisted = ""
        deprecated = ""

        # Get valid cipher suite for the version
        accepted = root_node.find("acceptedCipherSuites")

        # Browse the cipher list
        for cipher in accepted.iter('cipherSuite'):
            cipher_name = cipher.get("name")

            # Check if the cipher is not whitelisted
            if cipher_name not in self.whitelist_cipher:
                # Check if the cipher contains blacklisted term
                if any(bl_c in cipher_name for bl_c in self.blacklist_cipher):
                    # Add cipher to blacklist issue
                    if not blacklisted:
                        blacklisted += cipher_name
                    else:
                        blacklisted += ", " + cipher_name
                else:
                    # Add the cipher to unauthorized list
                    if not not_whitelisted:
                        not_whitelisted += cipher_name
                    else:
                        not_whitelisted += ", " + cipher_name

            # Check if the cipher is deprecated
            if any(dp_c in cipher_name for dp_c in self.deprecated_cipher):
                # Add the cipher to deprecated list
                if not deprecated:
                    deprecated += cipher_name
                else:
                    deprecated += ", " + cipher_name

        # Create issue for blacklisted cipher
        if blacklisted:
            issue = SSLYZE_ISSUES["blacklisted"].copy()
            issue["Summary"] = version + " - " + issue["Summary"]
            issue["Description"] += "\n\nBlacklisted encryption algorithms found :\n" + blacklisted
            issues.append(issue)

        # Create issue for unauthorized cipher
        if not_whitelisted:
            issue = SSLYZE_ISSUES["unauthorized"].copy()
            issue["Summary"] = version + " - " + issue["Summary"]
            issue["Description"] += "\n\nUnauthorized encryption algorithms found :\n" + not_whitelisted
            issues.append(issue)

        # Create issue for deprecated cipher
        if deprecated:
            issue = SSLYZE_ISSUES["deprecated"].copy()
            issue["Summary"] = version + " - " + issue["Summary"]
            issue["Description"] += "\n\nDeprecated encryption algorithms found :\n" + deprecated
            issues.append(issue)

        return issues

    # Check if the preferred cipher is the most secure accepted cipher
    # param:
    #   root_node :      xml element containing ciphers for a ssl/tls version
    #   version :   name of the version assessed like "tls V1.2"
    def check_cipher_order(self, root_node, version):
        issues = []

        # Get the name of the preferred cipher
        preferred = root_node.find("preferredCipherSuite")[0].get("name")

        # get index of preferred cipher
        try:
            pref_id = self.whitelist_cipher.index(preferred)
        except Exception:
            pref_id = len(self.whitelist_cipher) + 1

        accepted = root_node.find("acceptedCipherSuites")
        safer_cipher_id = pref_id
        safer_cipher = ""

        # Browse the ciphers list to find the most secure accepted cipher (best is the first of the white-list)
        for cipher in accepted.iter('cipherSuite'):
            cipher_name = cipher.get("name")

            # get index of accepted cipher
            if cipher_name in self.whitelist_cipher:
                acc_id = self.whitelist_cipher.index(cipher_name)
            else:
                continue

            # Check that no other accepted cipher has a lower index
            if acc_id < safer_cipher_id:
                safer_cipher_id = acc_id
                safer_cipher = cipher_name

        # Check if the preferred cipher is the best cipher from accepted regarding the white-list
        if safer_cipher_id < pref_id:
            issue = SSLYZE_ISSUES["no_order"].copy()

            issue["Summary"] = version + " - " + issue["Summary"]
            issue["Description"] += "\n\nPrefered cipher should be <em>" + safer_cipher + "</em> instead of <em>" \
                                    + preferred + "</em>"
            issues.append(issue)

        return issues

    def parse_sslyze_output(self, output):

        try:
            tree = ET.parse(output)
        except:
            raise Exception("The xml output can't be found or opened")

        root = tree.getroot()

        issues = []

        # Timeout or connection rejected ( invalid target )
        invalid_target = root.find(".//invalidTarget")
        if invalid_target is not None:
            self.sslyze_stderr = invalid_target.get("error")

        # Session Renegotiation
        session_renegotiation = root.find(".//sessionRenegotiation")
        if session_renegotiation is not None:
            if session_renegotiation.get("canBeClientInitiated") != "False":
                issues.append(SSLYZE_ISSUES["Client-initiated Renegotiations"])

            if session_renegotiation.get("isSecure") != "True":
                issues.append(SSLYZE_ISSUES["Secure Renegotiation"])

        # Compression
        compression = root.find(".//compression")
        if compression is not None and compression.find("compressionMethod") is not None:
            issues.append(SSLYZE_ISSUES["Compression"])

        # Heartbleed
        heartbleed = root.find(".//heartbleed/openSslHeartbleed")
        if heartbleed is not None and heartbleed.get("isVulnerable") != "False":
            issues.append(SSLYZE_ISSUES["Heartbleed"])

        # HSTS
        hsts = root.find(".//hsts/httpStrictTransportSecurity")
        if hsts is not None and hsts.get("isSupported") == "False":
            issues.append(SSLYZE_ISSUES["HSTS"])

        # Session Resumption
        session_resumption_with_session_ids = root.find(".//sessionResumptionWithSessionIDs")
        session_resumption_with_tls_tickets = root.find(".//sessionResumptionWithTLSTickets")

        if session_resumption_with_session_ids is not None:
            if session_resumption_with_session_ids.get("isSupported") != "True":
                issues.append(SSLYZE_ISSUES["Session ressumption with session IDs"])

        if session_resumption_with_tls_tickets is not None:
            if session_resumption_with_tls_tickets.get("isSupported") != "True":
                issues.append(SSLYZE_ISSUES["Session ressumption with TLS session tickets"])

        # Certificate - Content
        public_key_size = root.find(".//publicKeySize")
        if public_key_size is not None:
            key_size = int(public_key_size.text.split(" ")[0])
            if key_size < 2048:
                issue = SSLYZE_ISSUES["Public key size"]
                issue["Definition"] += "\n\nActually, the public key size found is " + key_size
                issues.append(issue)

        # Check if the certificate is expired
        not_after = root.find(".//validity/notAfter")
        if not_after is not None:
            date = not_after.text
            cert_date = time.strptime(date, "%b %d %H:%M:%S %Y GMT")
            if cert_date < time.gmtime():
                issue = SSLYZE_ISSUES["Expired Validity date"]
                issue["Description"] += "\n\nActually, the validity date found is " + date
                issues.append(issue)

        # Check if the certificate is before being valid
        not_before = root.find(".//validity/notBefore")
        if not_before is not None:
            date = not_before.text
            cert_date = time.strptime(date, "%b %d %H:%M:%S %Y GMT")
            if cert_date > time.gmtime():
                issue = SSLYZE_ISSUES["Before Validity date"]
                issue["Description"] += "\n\nActually, the validity date begins at " + date
                issues.append(issue)

        # Certificate - Trust:
        hostname_validation = root.find(".//hostnameValidation")

        if hostname_validation is not None:
            if hostname_validation.get("certificateMatchesServerHostname") != "True":
                issue = SSLYZE_ISSUES["Hostname validation"]

                # find the CommonName of the certificate
                common_name = root.find(".//certificate[@position='leaf']/subject/commonName").text
                issue["Description"] += "\n\nActually, the commonName for the certificate is " + common_name

                issues.append(issue)

        path_validations = root.findall(".//pathValidation")

        if path_validations:
            bad_cert_validation = ""
            for path_validation in path_validations:
                validation_result = path_validation.get("validationResult")
                if validation_result != "ok":
                    if not bad_cert_validation:
                        bad_cert_validation += str(path_validation.get("usingTrustStore")) + " : " + str(validation_result)
                    else:
                        bad_cert_validation += "\n" + path_validation.get("usingTrustStore") + " : " + validation_result

            if bad_cert_validation:
                issue = SSLYZE_ISSUES["Certificate validation"]
                issue["Description"] += "\n\nBad certificate validation for the following store(s) : \n" \
                                        + bad_cert_validation
                issues.append(issue)

        # SSLV2 Cipher Suites
        sslv2 = root.find(".//sslv2")
        if sslv2 is not None and sslv2.get("isProtocolSupported") == "True":
            accepted = sslv2.find("acceptedCipherSuites")
            preferred = sslv2.find("preferredCipherSuite")

            if accepted is not None or preferred is not None:
                if list(accepted) or list(preferred):

                    preferred_ciphers = [cipher.get("name") for cipher in list(preferred)]
                    accepted_ciphers = [cipher.get("name") for cipher in list(accepted)]

                    issue = SSLYZE_ISSUES["SSLV2"]
                    issue["Description"] += "\n\nList of accepted/preferred cipher suites : " + \
                                            "/ ".join(preferred_ciphers) + ", " + ", ".join(accepted_ciphers)
                    issues.append(issue)

        # SSLV3 Cipher Suites
        sslv3 = root.find(".//sslv3")
        if sslv3 is not None and sslv3.get("isProtocolSupported") == "True":
            accepted = sslv3.find("acceptedCipherSuites")
            preferred = sslv3.find("preferredCipherSuite")

            if accepted is not None or preferred is not None:
                if list(accepted) or list(preferred):

                    preferred_ciphers = [cipher.get("name") for cipher in list(preferred)]
                    accepted_ciphers = [cipher.get("name") for cipher in list(accepted)]

                    issue = SSLYZE_ISSUES["SSLV3_notempty"]
                    issue["Description"] += "\n\nList of accepted/preferred cipher suites : " + \
                                            ", ".join(preferred_ciphers) + "/ " + ", ".join(accepted_ciphers)
                    issues.append(issue)

        # TLSV1 Cipher Suites
        tlsv1 = root.find(".//tlsv1")
        if tlsv1 is not None and tlsv1.get("isProtocolSupported") == "True":
            issues.extend(self.filter_cipher(tlsv1, "TLS 1"))

            if self.enforce_order == "True":
                issues.extend(self.check_cipher_order(tlsv1, "TLS 1"))

        # TLSV1.1 Cipher Suites
        tlsv1_1 = root.find(".//tlsv1_1")
        if tlsv1_1 is not None and tlsv1_1.get("isProtocolSupported") == "True":
            issues.extend(self.filter_cipher(tlsv1_1, "TLS 1.1"))

            if self.enforce_order == "True":
                issues.extend(self.check_cipher_order(tlsv1_1, "TLS 1.1"))

        # TLSV1.2 Cipher Suites
        tlsv1_2 = root.find(".//tlsv1_2")
        if tlsv1_2 is not None and tlsv1_2.get("isProtocolSupported") == "True":
            issues.extend(self.filter_cipher(tlsv1_2, "TLS 1.2"))

            if self.enforce_order == "True":
                issues.extend(self.check_cipher_order(tlsv1_2, "TLS 1.2"))
        else:
            issues.append(SSLYZE_ISSUES["TLSV1_2_not_supported"])
        # For each issue add the hostname scanned in the URL field:
        for issue in issues:
            issue["URLs"] = [{"URL": self.target}]

        return issues

    def _check_options(self):
        args = []
        # General
        if "timeout" in self.configuration:
            args += ["--timeout", str(self.configuration["timeout"])]
        if "nb_retries" in self.configuration:
            args += ["--nb_retries", str(self.configuration["nb_retries"])]
        if "https_tunnel" in self.configuration:
            args += ["--https_tunnel", self.configuration["https_tunnel"]]
        if "starttls" in self.configuration:
            args += ["--starttls", self.configuration["starttls"]]
        if "xmpp_to" in self.configuration:
            args += ["--xmpp_to", self.configuration["xmlpp_to"]]
        if "sni" in self.configuration:
            args += ["--sni", self.configuration["sni"]]
        if "regular" in self.configuration:
            args += ["--regular"]

        # Client certificate support
        if "cert" in self.configuration:
            args += ["--cert", self.configuration["cert"]]
        if "certform" in self.configuration:
            args += ["--certform", self.configuration["certform"]]
        if "key" in self.configuration:
            args += ["--key", self.configuration["key"]]
        if "keyform" in self.configuration:
            args += ["--keyform", self.configuration["keyform"]]
        if "pass" in self.configuration:
            args += ["--pass", self.configuration["pass"]]

        # PluginCertInfo
        if "certinfo" in self.configuration:
            args += ["--certinfo", self.configuration["certinfo"]]

        # PluginHeartbleed
        if "heartbleed" in self.configuration:
            args += ["--heartbleed"]

        # PluginSessionResumption
        if "resum" in self.configuration:
            args += ["--resum"]
        if "resum_rate" in self.configuration:
            args += ["--resum_rate"]

        # PluginOpenSSLCipherSuite
        if "sslv2" in self.configuration:
            args += ["--sslv2"]
        if "sslv3" in self.configuration:
            args += ["--sslv3"]
        if "tlsv1" in self.configuration:
            args += ["--tlsv1"]
        if "tlsv1_1" in self.configuration:
            args += ["--tlsv1_1"]
        if "tlsv1_2" in self.configuration:
            args += ["--tlsv1_2"]
        if "http_get" in self.configuration:
            args += ["--http_get"]
        if "hide_rejected_ciphers" in self.configuration:
            args += ["--hide_rejected_ciphers"]

        # PluginCompression
        if "compression" in self.configuration:
            args += ["--compression"]

        # PluginSessionRenegotation
        if "reneg" in self.configuration:
            args += ["--reneg"]

        # PluginHSTS
        if "hsts" in self.configuration:
            args += ["--hsts"]

        # Get additional parameters
        params = []
        if 'parameters' in self.configuration:
            params = self.configuration.get('parameters')

            # Put parameters into array
            params = params.split()
            args += params

        return args

    def do_configure(self):

        self.export_cipher_suites = []
        self.anonymous_dh_cipher_suites = []
        self.null_cipher_suites = []
        self.low_ciphers_suites = []

        self.blacklist_cipher = []
        self.whitelist_cipher = []

        self.deprecated_cipher = []

        self.enforce_order = "False"

        if "export_cipher_suites" in self.configuration:
            self.export_cipher_suites = self.configuration["export_cipher_suites"].split(':')
        if "anonymous_dh_cipher_suites" in self.configuration:
            self.anonymous_dh_cipher_suites = self.configuration["anonymous_dh_cipher_suites"].split(':')
        if "null_cipher_suites" in self.configuration:
            self.null_cipher_suites = self.configuration["null_cipher_suites"].split(':')
        if "low_cipher_suites" in self.configuration:
            self.low_ciphers_suites = self.configuration["low_cipher_suites"].split(':')

        if "blacklist_cipher" in self.configuration:
            self.blacklist_cipher = self.configuration["blacklist_cipher"].split(':')

        if "whitelist_cipher" in self.configuration:
            self.whitelist_cipher = self.configuration["whitelist_cipher"].split(':')

        if "enforce_order" in self.configuration:
            self.enforce_order = self.configuration["enforce_order"]

        if "deprecated" in self.configuration:
            self.deprecated_cipher = self.configuration["deprecated"].split(':')

    def do_start(self):

        # Try to find sslyze with the given configuration
        if "sslyze_path" in self.configuration:
            sslyze_path = self.configuration["sslyze_path"]

            if not os.path.isfile(sslyze_path):
                raise Exception("Cannot find SSlyze with the given path")

        # Else try to find sslyze in the path
        else:
            sslyze_path = self.locate_program(self.SSLyze_NAME)
            if sslyze_path is None:
                raise Exception("Cannot find SSLyze in path")

        if 'report_dir' in self.configuration:
            self.report_dir = self.configuration['report_dir']
        else:
            self.report_dir = os.path.dirname(os.path.realpath(__file__)) + "/artifacts/"

        self.sslyze_stdout = ""
        self.sslyze_stderr = ""

        url = urlparse(self.configuration['target'])
        self.target = url.hostname

        # Check if the target is an ip to avoid empty hostname
        if not self.target:
            self.target = url.path

        self.output_id = str(uuid.uuid4())
        self.xml_output = self.report_dir + "XMLOUTPUT_" + self.output_id + ".xml"

        args = self._check_options()
        args += ["--xml_out", self.xml_output]
        args += [self.target]

        self.spawn(sslyze_path, args)

    def do_process_stdout(self, data):
        self.sslyze_stdout += data

    def do_process_stderr(self, data):
        self.sslyze_stderr += data

    def do_process_ended(self, status):
        if self.stopping and status == 9:
            self.report_finish("STOPPED")
        elif status == 0:
            issues = self.parse_sslyze_output(self.xml_output)
            self.report_issues(issues)

            self._save_artifacts()

            if self.sslyze_stderr:
                failure = {
                    "hostname": socket.gethostname(),
                    "exception": self.sslyze_stderr,
                    "message": "Plugin failed"
                }
                self.report_finish("FAILED", failure)
            else:
                self.report_finish()
        else:
            self._save_artifacts()
            failure = {
                "hostname": socket.gethostname(),
                "exception": self.sslyze_stderr,
                "message": "Plugin failed"
            }
            self.report_finish("FAILED", failure)

    def _save_artifacts(self):
        stdout_log = self.report_dir + "STDOUT_" + self.output_id + ".txt"
        stderr_log = self.report_dir + "STDERR_" + self.output_id + ".txt"
        output_artifacts = []

        if self.sslyze_stdout:
            with open(stdout_log, 'w+') as f:
                f.write(self.sslyze_stdout)
            output_artifacts.append(stdout_log)
        if self.sslyze_stderr:
            with open(stderr_log, 'w+') as f:
                f.write(self.sslyze_stderr)
            output_artifacts.append(stderr_log)

        if output_artifacts:
            self.report_artifacts("SSLyze Output", output_artifacts)
        if os.path.isfile(self.xml_output):
            self.report_artifacts("SSLyze XML Report", [self.xml_output])