# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import datetime
import time
import os
import xml.etree.cElementTree as ET
import uuid
import socket
from urlparse import urlparse
from minion.plugins.base import ExternalProcessPlugin

from issues import IssueManager


class SSLyzePlugin(ExternalProcessPlugin):
    PLUGIN_NAME = "SSlyze"
    PLUGIN_VERSION = "0.14.1"
    PLUGIN_WEIGHT = "light"

    SSLyze_NAME = "sslyze"

    MINIMUM_PUB_KEY_SIZE_RSA = 2048
    MINIMUM_PUB_KEY_SIZE_ECCD = 256

    issue_manager = IssueManager()

    # Browse accepted ciphers and check whether they are blacklisted or whitelisted
    # param:
    #   root_node :      xml element containing ciphers for a ssl/tls version
    #   version :   name of the version assessed like "tls V1.2"
    def filter_cipher(self, root_node, version, need_FS=False):
        blacklisted = ""
        not_whitelisted = ""
        deprecated = ""

        fs_counter = 0

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

            # Check if at least one filter supports Forward Secrecy
            if any(dp_c in cipher_name for dp_c in self.forward_sec_cipher):
                fs_counter += 1

        # Create issue for blacklisted cipher
        if blacklisted:
            self.issue_manager.blacklisted_cipher(version, blacklisted)

        # Create issue for unauthorized cipher
        if not_whitelisted:
            self.issue_manager.unauthorized_cipher(version, not_whitelisted)

        # Create issue for deprecated cipher
        if deprecated:
            self.issue_manager.deprecated_cipher(version, deprecated)

        # Create issue if no cipher supports Forward Secrecy
        if fs_counter == 0 and need_FS:
            self.issue_manager.no_ats_valid({"support_fs": False})

    # Check if the preferred cipher is the most secure accepted cipher
    # param:
    #   root_node :      xml element containing ciphers for a ssl/tls version
    #   version :   name of the version assessed like "tls V1.2"
    def check_cipher_order(self, root_node, version):
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
            self.issue_manager.no_cipher_order(version, safer_cipher, preferred)

    # Checks the validity of wildcard usage
    # param :
    #   urls : array containing address or commonName or AlternativeName to check
    def check_wildcard(self, urls):
        mixed_wildcard = []
        bad_level_wildcard = []

        for url in urls:
            # Check if url contains a wildcard
            if "*" not in url:
                continue

            # Remove the protocol from the url if any
            url = url.replace("https://", "")
            url = url.replace("http://", "")

            url_elements = url.split('.')
            # url_elements = ["abcde","co","uk"]

            # Check that the lowest level doesn't contains a word with wildcard like *domain
            if "*" in url_elements[0] and len(url_elements[0]) > 1:
                mixed_wildcard.append(url)
                continue

            # Try to find the tld from longest to shortest
            for i in range(-len(url_elements), 0):
                last_i_elements = url_elements[i:]
                #    i=-3: ["abcde","co","uk"]
                #    i=-2: ["co","uk"]
                #    i=-1: ["uk"] etc

                # Rebuild the url
                candidate = ".".join(last_i_elements)  # abcde.co.uk, co.uk, uk

                if candidate in self.tlds:
                    # Remove the tld from the url
                    domains = list(set(url_elements) - set(last_i_elements))

                    # Check the number of subdomains is greated for the wildcard than specified
                    if len(domains) < self.wildcard_level:
                        bad_level_wildcard.append(url)

        # Create issue for mixed domain with wildcard
        if mixed_wildcard:
            self.issue_manager.wrong_wildcard(mixed_wildcard)

        if bad_level_wildcard:
            self.issue_manager.domain_wildcard(bad_level_wildcard)

    def parse_sslyze_output(self, output):

        try:
            tree = ET.parse(output)
        except:
            raise Exception("The xml output can't be found or opened")

        root = tree.getroot()

        issues = []

        # Check error
        for target_error in root.find('.//invalidTargets'):
            # TODO create error issue
            # Timeout or connection rejected ( invalid target )
            self.sslyze_stderr += target_error.get("error") + "\n"

        for result in root.find('.//results'):
            # Retrieve the IP
            target_ip = result.get('ip')

            # Set the target
            self.issue_manager.new_target(target_ip)

            # Session Renegotiation
            session_renegotiation = result.find(".//sessionRenegotiation")
            if session_renegotiation is not None:
                if session_renegotiation.get("canBeClientInitiated") != "False":
                    self.issue_manager.client_renegotiation()

                if session_renegotiation.get("isSecure") != "True":
                    self.issue_manager.secure_renegotiation()

            # Compression
            compression = result.find(".//compression")
            if compression is not None and compression.find("compressionMethod") is not None:
                # Check every compression methods
                supported_compression = []
                for compression_method in compression:
                    if compression_method.get("isSupported") != "False":
                        supported_compression.append(compression_method.get('type'))

                # Create issue if faulty compression is found
                if supported_compression:
                    self.issue_manager.insecure_compression(supported_compression)

            # Heartbleed
            heartbleed = result.find(".//heartbleed/openSslHeartbleed")
            if heartbleed is not None and heartbleed.get("isVulnerable") != "False":
                self.issue_manager.heartbleed()

            # HSTS
            hsts = result.find(".//http_headers/httpStrictTransportSecurity")
            if hsts is not None and hsts.get("isSupported") == "False":
                self.issue_manager.no_hsts()

            # Session Resumption
            session_resumption_with_session_ids = result.find(".//sessionResumptionWithSessionIDs")
            session_resumption_with_tls_tickets = result.find(".//sessionResumptionWithTLSTickets")

            if session_resumption_with_session_ids is not None:
                if session_resumption_with_session_ids.get("isSupported") != "True":
                    self.issue_manager.session_resumption_id()

            if session_resumption_with_tls_tickets is not None:
                if session_resumption_with_tls_tickets.get("isSupported") != "True":
                    self.issue_manager.session_resumption_ticket()

            # Check if ocspStapling is activated
            ocsp = result.find(".//ocspStapling")
            if ocsp is None or ocsp.get("isSupported") == "False":
                self.issue_manager.no_ocsp_stapling()

            cert_hash = None
            signed_by = None

            # Get certificate analysis error
            try:
                cert_error = result.find(".//certinfo").get("exception")
            except:
                cert_error = None

            # Check if the certificate is enforced and sslyze got results
            if "certinfo" in self.configuration and not cert_error:
                # Certificate - Content
                public_key_size = result.find(".//publicKeySize")
                if public_key_size is not None:
                    key_size = int(public_key_size.text.split(" ")[0])

                    # Check conformance to ATS
                    pub_key_algo = result.find(".//publicKeyAlgorithm")
                    if pub_key_algo is not None:
                        # Case RSA
                        if pub_key_algo.text == "rsaEncryption" and key_size < self.MINIMUM_PUB_KEY_SIZE_RSA:
                            self.issue_manager.no_ats_valid({"pub_key_size": str(key_size), "pub_key_algo": "RSA"})
                            self.issue_manager.low_key_size(self.MINIMUM_PUB_KEY_SIZE_RSA, str(key_size))
                        elif pub_key_algo.text == "id-ecPublicKey" and key_size < self.MINIMUM_PUB_KEY_SIZE_ECCD:
                            self.issue_manager.no_ats_valid({"pub_key_size": str(key_size), "pub_key_algo": "ECDSA"})
                            self.issue_manager.low_key_size(self.MINIMUM_PUB_KEY_SIZE_ECCD, str(key_size))

                # Get current time used for verification
                today = datetime.date.today().strftime("%b %d %H:%M:%S %Y GMT")

                # Check if the certificate is expired
                not_after = result.find(".//validity/notAfter")
                if not_after is not None:
                    date = not_after.text
                    cert_date = time.strptime(date, "%b %d %H:%M:%S %Y GMT")
                    if cert_date < time.gmtime():
                        self.issue_manager.certificate_expired(date, today)

                # Check if the certificate is before being valid
                not_before = result.find(".//validity/notBefore")
                if not_before is not None:
                    date = not_before.text
                    cert_date = time.strptime(date, "%b %d %H:%M:%S %Y GMT")
                    if cert_date > time.gmtime():
                        self.issue_manager.certificate_not_valid_yet(date, today)

                try:
                    common_name = result.find(".//certificate[@position='leaf']/subject/commonName").text
                except AttributeError as e:
                    common_name = "Error Cloud Not get the Certificate Info"

                # Build a list of valid hostname
                names = [common_name]

                # Get alternativeNames
                alternative_names = result.find(".//certificate[@position='leaf']"
                                                "/extensions/X509v3SubjectAlternativeName/DNS")
                if alternative_names is not None:
                    for list_entry in alternative_names:
                        names.append(list_entry.text)

                # Certificate hostname validation
                hostname_validation = result.find(".//hostnameValidation")
                if hostname_validation is not None:
                    if hostname_validation.get("certificateMatchesServerHostname") != "True":
                        self.issue_manager.no_hostname_validation(self.target, names)

                # Check wildcard for CommonName and AlternativeNames
                self.check_wildcard(names)

                # Check if the certificate chain is in the correct order
                chain_order = result.find(".//receivedCertificateChain").get('isChainOrderValid')
                if chain_order != "True":
                    self.issue_manager.wrong_chain_order()

                # Check if the certificate is signed with sha1
                sha1_node = result.find(".//verifiedCertificateChain")
                if sha1_node:
                    signed_with_sha1 = sha1_node.get('hasSha1SignedCertificate')
                    if signed_with_sha1 == "True":
                        # Check only the leaf certificate for the moment
                        signature_algo = result.find(".//certificate[@position='leaf']/signatureAlgorithm").text

                        if "sha1" in signature_algo:
                            self.issue_manager.signed_with_sha1()
                            self.issue_manager.no_ats_valid({"sha1": True})

                # Get the certificate hash
                cert_hash = result.find(".//certificate[@position='leaf']").get('sha1Fingerprint')

                # Get the organization that certified the certificate
                signed_by = result.find(".//certificate[@position='leaf']/issuer/organizationName").text

                # Check certificate validation from CA
                path_validations = result.findall(".//pathValidation")
                if path_validations:
                    bad_cert_validation = ""
                    for path_validation in path_validations:
                        validation_result = path_validation.get("validationResult")
                        if validation_result != "ok":
                            # Check if only the custom CA matters
                            if (self.only_custom_CA and path_validation.get("usingTrustStore") == "Custom --ca_file") \
                                    or not self.only_custom_CA:
                                # Get possible error message
                                error_result = path_validation.get("error")

                                bad_cert_validation += str(path_validation.get("usingTrustStore")) + \
                                                       " : " + str(error_result or validation_result) + "<br/>"

                    if bad_cert_validation:
                        # Check if the grey-false positive from Mozilla due to extra cert is important
                        ignore_nss = self.configuration.get("ignore_extra_cert")
                        if bad_cert_validation == "Mozilla NSS : unable to get local issuer certificate<br/>" \
                                and ignore_nss:
                            self.issue_manager.extra_cert()
                        else:
                            self.issue_manager.certificate_not_valid(bad_cert_validation)
            # Check if SSLyze couldn't get the certificate
            elif cert_error:
                self.issue_manager.certificate_not_found(cert_error)

            # Raise info
            else:
                self.issue_manager.certificate_not_checked()

            # TODO refactor ssl/tls check
            # SSL V2 Cipher Suites
            sslv2 = result.find(".//sslv2")
            if sslv2 is not None and sslv2.get("isProtocolSupported") == "True":
                accepted = sslv2.find("acceptedCipherSuites")
                preferred = sslv2.find("preferredCipherSuite")

                if accepted is not None or preferred is not None:
                    if list(accepted) or list(preferred):

                        preferred_ciphers = [cipher.get("name") for cipher in list(preferred)]
                        accepted_ciphers = [cipher.get("name") for cipher in list(accepted)]

                        self.issue_manager.support_sslv2(preferred_ciphers, accepted_ciphers)

            # SSL V3 Cipher Suites
            sslv3 = result.find(".//sslv3")
            if sslv3 is not None and sslv3.get("isProtocolSupported") == "True":
                accepted = sslv3.find("acceptedCipherSuites")
                preferred = sslv3.find("preferredCipherSuite")

                if accepted is not None or preferred is not None:
                    if list(accepted) or list(preferred):

                        preferred_ciphers = [cipher.get("name") for cipher in list(preferred)]
                        accepted_ciphers = [cipher.get("name") for cipher in list(accepted)]

                        self.issue_manager.support_sslv3(preferred_ciphers, accepted_ciphers)

            # TLS V1 Cipher Suites
            tlsv1 = result.find(".//tlsv1")
            if tlsv1 is not None and tlsv1.get("isProtocolSupported") == "True":
                self.filter_cipher(tlsv1, "TLS 1")

                if self.enforce_order == "True":
                    self.check_cipher_order(tlsv1, "TLS 1")

            # TLS V1.1 Cipher Suites
            tlsv1_1 = result.find(".//tlsv1_1")
            if tlsv1_1 is not None and tlsv1_1.get("isProtocolSupported") == "True":
                self.filter_cipher(tlsv1_1, "TLS 1.1")

                if self.enforce_order == "True":
                    self.check_cipher_order(tlsv1_1, "TLS 1.1")

            # TLS V1.2 Cipher Suites
            tlsv1_2 = result.find(".//tlsv1_2")
            if tlsv1_2 is not None and tlsv1_2.get("isProtocolSupported") == "True":
                self.filter_cipher(tlsv1_2, "TLS 1.2", True)

                if self.enforce_order == "True":
                    self.check_cipher_order(tlsv1_2, "TLS 1.2")
            else:
                self.issue_manager.no_tls_v1_2()
                self.issue_manager.no_ats_valid({"support_tls_v1_2": False})

            # Prepare information to add for the target:
            infos = {"URL": self.target, "IP": target_ip, "CA": cert_hash, "issuer": signed_by}
            self.issue_manager.add_target_info(infos)

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
            args += ["--certinfo_%s" % self.configuration["certinfo"]]

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
            args += ["--http_headers"]

        # External --ca_file
        if "ca_file" in self.configuration:
            args += ["--ca_file", self.configuration["ca_file"]]

        # Get additional parameters
        params = []
        if 'parameters' in self.configuration:
            params = self.configuration.get('parameters')

            # Put parameters into array
            params = params.split()
            args += params

        return args

    def do_configure(self):
        self.blacklist_cipher = []
        self.whitelist_cipher = []
        self.deprecated_cipher = []
        self.forward_sec_cipher = []

        self.enforce_order = "False"
        self.tlds = []
        self.wildcard_level = -1

        if "blacklist_cipher" in self.configuration:
            self.blacklist_cipher = self.configuration["blacklist_cipher"].split(':')

        if "whitelist_cipher" in self.configuration:
            self.whitelist_cipher = self.configuration["whitelist_cipher"].split(':')

        if "forward_sec_cipher" in self.configuration:
            self.forward_sec_cipher = self.configuration["forward_sec_cipher"].split(':')

        if "enforce_order" in self.configuration:
            self.enforce_order = self.configuration["enforce_order"]

        if "deprecated" in self.configuration:
            self.deprecated_cipher = self.configuration["deprecated"].split(':')

        if "wildcard_level" in self.configuration:
            self.wildcard_level = int(self.configuration["wildcard_level"])

            if "tld_path" in self.configuration:
                with open(self.configuration["tld_path"]) as tld_file:
                    self.tlds = [line.strip() for line in tld_file if line[0] not in "/\n"]

        # Check only against defined CA (array)
        if "only_custom_CA" in self.configuration:
            self.only_custom_CA = self.configuration["only_custom_CA"]
        else:
            self.only_custom_CA = False

        # Check if SSLyze must scan every A record for given hostname
        if "resolve_ip" in self.configuration:
            self.resolve_ip = self.configuration["resolve_ip"]
        else:
            self.resolve_ip = False

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

        # Check if the plugin needs to pull A records from target
        if self.resolve_ip:
            # Check if the module is installed
            try:
                import dns.resolver

                answer = dns.resolver.query(self.target, 'A')

                for ip in answer:
                    target = "%s{%s}" % (self.target, ip)
                    args += [target]
            except:
                raise Exception("Cannot load dnspython library, can't resolve ip from target")
        else:
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
            self.parse_sslyze_output(self.xml_output)

            issues = self.issue_manager.generate_issues()

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