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
        "Severity": "High",
        "Description": "Test the server for client-initiated renegotiation support",
        "Classification": {
            "cwe_id": "310",
            "cwe_url": "http://cwe.mitre.org/data/definitions/310.html"
        }
    },
    "Secure Renegotiation":  {
        "Summary": "Secure Renegotiation - Not supported",
        "Severity": "High",
        "Description": "Test the server for secure renegotiation support",
        "Classification": {
            "cwe_id": "310",
            "cwe_url": "http://cwe.mitre.org/data/definitions/310.html"
        }
    },
    "Compression": {
        "Summary": "Compression - Supported",
        "Severity": "Low",
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
    "Public key size": {
        "Summary": "Public key size lower than 2048 bits",
        "Severity": "High",
        "Description": "Verify that the the public key size is not lower than 2048 bits",
        "Classification": {
            "cwe_id": "320",
            "cwe_url": "http://cwe.mitre.org/data/definitions/320.html"
        }
    },
    "Validity date": {
        "Summary": "Validity date before current date",
        "Severity": "High",
        "Description": "Verify that the validity date of the certificate is not before the current date",
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
    "SSLV3_exp_ciphers": {
        "Summary": "SSL 3.0 -  List of accepted cipher suites contains export encryption algorithms",
        "Severity": "High",
        "Description": "The SSL 3.0 OpenSSL cipher suites supported by the server contains "
                       "export encryption algorithms which are not secure",
        "Classification": {
            "cwe_id": "327",
            "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
        }
    },
    "SSLV3_adh_ciphers": {
        "Summary": "SSL 3.0 -  List of accepted cipher suites contains anonymous DH cipher suites",
        "Severity": "High",
        "Description": "The SSL 3.0 OpenSSL cipher suites supported by the server contains "
                       "anonymous DH cipher suites which are not secure",
        "Classification": {
            "cwe_id": "327",
            "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
        }
    },
    "SSLV3_null_ciphers": {
        "Summary": "SSL 3.0 -  List of accepted cipher suites contains \"NULL\" ciphers",
        "Severity": "High",
        "Description": "The SSL 3.0 OpenSSL cipher suites supported by the server contains "
                       "\"NULL\" ciphers which are not secure",
        "Classification": {
            "cwe_id": "327",
            "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
        }
    },
    "SSLV3_low_ciphers": {
        "Summary": "SSL 3.0 -  List of accepted cipher suites contains \"low\" encryption cipher suites",
        "Severity": "High",
        "Description": "The SSL 3.0 OpenSSL cipher suites supported by the server contains "
                       "\"low\" encryption cipher suites which are not secure",
        "Classification": {
            "cwe_id": "327",
            "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
        }
    },
    "TLSV1_exp_ciphers": {
        "Summary": "TLS 1.0 -  List of accepted cipher suites contains export encryption algorithms",
        "Severity": "High",
        "Description": "The TLS 1.0 OpenSSL cipher suites supported by the server contains "
                       "export encryption algorithms which are not secure",
        "Classification": {
            "cwe_id": "327",
            "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
        }
    },
    "TLSV1_adh_ciphers": {
        "Summary": "TLS 1.0 -  List of accepted cipher suites contains anonymous DH cipher suites",
        "Severity": "High",
        "Description": "The TLS 1.0 OpenSSL cipher suites supported by the server contains "
                       "anonymous DH cipher suites which are not secure",
        "Classification": {
            "cwe_id": "327",
            "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
        }
    },
    "TLSV1_null_ciphers": {
        "Summary": "TLS 1.0 -  List of accepted cipher suites contains \"NULL\" ciphers",
        "Severity": "High",
        "Description": "The TLS 1.0 OpenSSL cipher suites supported by the server contains "
                       "\"NULL\" ciphers which are not secure",
        "Classification": {
            "cwe_id": "327",
            "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
        }
    },
    "TLSV1_low_ciphers": {
        "Summary": "TLS 1.0 -  List of accepted cipher suites contains \"low\" encryption cipher suites",
        "Severity": "High",
        "Description": "The TLS 1.0 OpenSSL cipher suites supported by the server contains "
                       "\"low\" encryption cipher suites which are not secure",
        "Classification": {
            "cwe_id": "327",
            "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
        }
    },
    "TLSV1_1_exp_ciphers": {
        "Summary": "TLS 1.1 -  List of accepted cipher suites contains export encryption algorithms",
        "Severity": "High",
        "Description": "The TLS 1.1 OpenSSL cipher suites supported by the server contains "
                       "export encryption algorithms which are not secure",
        "Classification": {
            "cwe_id": "327",
            "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
        }
    },
    "TLSV1_1_adh_ciphers": {
        "Summary": "TLS 1.1 -  List of accepted cipher suites contains anonymous DH cipher suites",
        "Severity": "High",
        "Description": "The TLS 1.1 OpenSSL cipher suites supported by the server contains "
                       "anonymous DH cipher suites which are not secure",
        "Classification": {
            "cwe_id": "327",
            "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
        }
    },
    "TLSV1_1_null_ciphers": {
        "Summary": "TLS 1.1 -  List of accepted cipher suites contains \"NULL\" ciphers",
        "Severity": "High",
        "Description": "The TLS 1.1 OpenSSL cipher suites supported by the server contains "
                       "\"NULL\" ciphers which are not secure",
        "Classification": {
            "cwe_id": "327",
            "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
        }
    },
    "TLSV1_1_low_ciphers": {
        "Summary": "TLS 1.1 -  List of accepted cipher suites contains \"low\" encryption cipher suites",
        "Severity": "High",
        "Description": "The TLS 1.1 OpenSSL cipher suites supported by the server contains "
                       "\"low\" encryption cipher suites which are not secure",
        "Classification": {
            "cwe_id": "327",
            "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
        }
    },
    "TLSV1_2_not_supported": {
        "Summary": "TLS 1.2 - Not supported",
        "Severity": "Medium",
        "Description": "TLS 1.2 is not supported by this server",
        "Classification": {
            "cwe_id": "327",
            "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
        }
    },
    "TLSV1_2_exp_ciphers": {
        "Summary": "TLS 1.2 -  List of accepted cipher suites contains export encryption algorithms",
        "Severity": "High",
        "Description": "The TLS 1.2 OpenSSL cipher suites supported by the server contains "
                       "export encryption algorithms which are not secure",
        "Classification": {
            "cwe_id": "327",
            "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
        }
    },
    "TLSV1_2_adh_ciphers": {
        "Summary": "TLS 1.2 -  List of accepted cipher suites contains anonymous DH cipher suites",
        "Severity": "High",
        "Description": "The TLS 1.2 OpenSSL cipher suites supported by the server contains "
                       "anonymous DH cipher suites which are not secure",
        "Classification": {
            "cwe_id": "327",
            "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
        }
    },
    "TLSV1_2_null_ciphers": {
        "Summary": "TLS 1.2 -  List of accepted cipher suites contains \"NULL\" ciphers",
        "Severity": "High",
        "Description": "The TLS 1.2 OpenSSL cipher suites supported by the server contains "
                       "\"NULL\" ciphers which are not secure",
        "Classification": {
            "cwe_id": "327",
            "cwe_url": "http://cwe.mitre.org/data/definitions/327.html"
        }
    },
    "TLSV1_2_low_ciphers": {
        "Summary": "TLS 1.2 -  List of accepted cipher suites contains \"low\" encryption cipher suites",
        "Severity": "High",
        "Description": "The TLS 1.2 OpenSSL cipher suites supported by the server contains "
                       "\"low\" encryption cipher suites which are not secure",
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

    def _find_weak_ciphers(self, root, version):
        issues = []
        accepted = root.find("acceptedCipherSuites")
        preferred = root.find("preferredCipherSuite")
        exp_cipher_suite = ""
        adh_cipher_suite = ""
        null_cipher_suite = ""
        low_cipher_suite = ""

        for cipher in accepted.iter('cipherSuite'):
            cipher_name = cipher.get("name")
            if cipher_name in self.export_cipher_suites:
                if not exp_cipher_suite:
                    exp_cipher_suite += cipher_name
                else:
                    exp_cipher_suite += ", " + cipher_name
            elif cipher_name in self.anonymous_dh_cipher_suites:
                if not adh_cipher_suite:
                    adh_cipher_suite += cipher_name
                else:
                    adh_cipher_suite += ", " + cipher_name
            elif cipher_name in self.null_cipher_suites:
                if not null_cipher_suite:
                    null_cipher_suite += cipher_name
                else:
                    null_cipher_suite += ", " + cipher_name
            elif cipher_name in self.low_ciphers_suites:
                if not low_cipher_suite:
                    low_cipher_suite += cipher_name
                else:
                    low_cipher_suite += ", " + cipher_name

        for cipher in preferred.iter('cipherSuite'):
            cipher_name = cipher.get("name")
            if cipher_name in self.export_cipher_suites:
                if not exp_cipher_suite:
                    exp_cipher_suite += cipher_name
                else:
                    exp_cipher_suite += ", " + cipher_name
            elif cipher_name in self.anonymous_dh_cipher_suites:
                if not adh_cipher_suite:
                    adh_cipher_suite += cipher_name
                else:
                    adh_cipher_suite += ", " + cipher_name
            elif cipher_name in self.null_cipher_suites:
                if not null_cipher_suite:
                    null_cipher_suite += cipher_name
                else:
                    null_cipher_suite += ", " + cipher_name
            elif cipher_name in self.low_ciphers_suites:
                if not low_cipher_suite:
                    low_cipher_suite += cipher_name
                else:
                    low_cipher_suite += ", " + cipher_name

        if exp_cipher_suite:
            issue = SSLYZE_ISSUES[version + "_exp_ciphers"]
            issue["Description"] += "\n\nExport encryption algorithms found " + exp_cipher_suite
            issues.append(issue)
        if adh_cipher_suite:
            issue = SSLYZE_ISSUES[version + "_adh_ciphers"]
            issue["Description"] += "\n\nAnonymous DH cipher suites found " + adh_cipher_suite
            issues.append(issue)
        if null_cipher_suite:
            issue = SSLYZE_ISSUES[version + "_null_ciphers"]
            issue["Description"] += "\n\n\"NULL\" ciphers found " + null_cipher_suite
            issues.append(issue)
        if low_cipher_suite:
            issue = SSLYZE_ISSUES[version + "_low_ciphers"]
            issue["Description"] += "\"low\" encryption cipher suites found " + low_cipher_suite
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
        heartbleed = root.find(".//heartbleed/heartbleed")
        if heartbleed is not None and heartbleed.get("isVulnerable") != "False":
            issues.append(SSLYZE_ISSUES["Heartbleed"])

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

        not_after = root.find(".//validity/notAfter")
        if not_after is not None:
            date = not_after.text
            datetime = time.strptime(date, "%b %d %H:%M:%S %Y GMT")
            if datetime < time.time():
                issue = SSLYZE_ISSUES["Public key size"]
                issue["Definition"] += "\n\nActually, the validity date found is " + date
                issues.append(SSLYZE_ISSUES["Validity date"])

        # Certificate - Trust:
        hostname_validation = root.find(".//hostnameValidation")

        if hostname_validation is not None:
            if hostname_validation.get("certificateMatchesServerHostname") != "True":
                issues.append(SSLYZE_ISSUES["Hostname validation"])

        path_validations = root.findall(".//pathValidation")

        if path_validations:
            bad_cert_validation = ""
            for path_validation in path_validations:
                if path_validation.get("validationResult") != "ok":
                    if not bad_cert_validation:
                        bad_cert_validation += path_validation.get("usingTrustStore")
                    else:
                        bad_cert_validation += ", " + path_validation.get("usingTrustStore")

            if bad_cert_validation:
                issue = SSLYZE_ISSUES["Certificate validation"]
                issue["Description"] += "\n\nBad certificate validation for the following store(s) : " + bad_cert_validation
                issues.append(issue)

        # SSLV2 Cipher Suites
        sslv2 = root.find(".//sslv2")
        if sslv2 is not None:
            accepted = sslv2.find("acceptedCipherSuites")
            preferred = sslv2.find("preferredCipherSuite")

            if accepted is not None and preferred is not None:
                if list(accepted) or list(preferred):

                    preferred_ciphers = [cipher.get("name") for cipher in list(preferred)]
                    accepted_ciphers = [cipher.get("name") for cipher in list(accepted)]

                    issue = SSLYZE_ISSUES["SSLV2"]
                    issue["Description"] += "\n\nList of accepted/preferred cipher suites : " + ", ".join(preferred_ciphers) + ", " + ", ".join(accepted_ciphers)
                    issues.append(issue)

        # SSLV3 Cipher Suites
        sslv3 = root.find(".//sslv3")
        if sslv3 is not None:
            accepted = sslv3.find("acceptedCipherSuites")
            preferred = sslv3.find("preferredCipherSuite")

            if accepted is not None and preferred is not None:
                if list(accepted) or list(preferred):

                    preferred_ciphers = [cipher.get("name") for cipher in list(preferred)]
                    accepted_ciphers = [cipher.get("name") for cipher in list(accepted)]

                    issue = SSLYZE_ISSUES["SSLV3_notempty"]
                    issue["Description"] += "\n\nList of accepted/preferred cipher suites : " + ", ".join(preferred_ciphers) + ", " + ", ".join(accepted_ciphers)
                    issues.append(issue)

            issues.extend(self._find_weak_ciphers(sslv3, "SSLV3"))

        # TLSV1 Cipher Suites
        tlsv1 = root.find(".//tslv1")
        if tlsv1 is not None:
            issues.extend(self._find_weak_ciphers(tlsv1, "TLSV1"))

        # TLSV1.1 Cipher Suites
        tlsv1_1 = root.find(".//tlsv1_1")
        if tlsv1_1 is not None:
            issues.extend(self._find_weak_ciphers(tlsv1_1, "TLSV1_1"))

        # TLSV1.2 Cipher Suites
        tlsv1_2 = root.find(".//tlsv1_2")
        if tlsv1_2 is not None:
            issues.extend(self._find_weak_ciphers(tlsv1_2, "TLSV1_2"))

            accepted = root.find("acceptedCipherSuites")
            preferred = root.find("preferredCipherSuite")

            if not accepted and not preferred:
                issues.append(SSLYZE_ISSUES["TLSV1_2_not_supported"])
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

        return args

    def do_configure(self):

        self.export_cipher_suites = []
        self.anonymous_dh_cipher_suites = []
        self.null_cipher_suites = []
        self.low_ciphers_suites = []

        if "export_cipher_suites" in self.configuration:
            self.export_cipher_suites = self.configuration["export_cipher_suites"].split(':')
        if "anonymous_dh_cipher_suites" in self.configuration:
            self.anonymous_dh_cipher_suites = self.configuration["anonymous_dh_cipher_suites"].split(':')
        if "null_cipher_suites" in self.configuration:
            self.null_cipher_suites = self.configuration["null_cipher_suites"].split(':')
        if "low_cipher_suites" in self.configuration:
            self.low_ciphers_suites = self.configuration["low_cipher_suites"].split(':')

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