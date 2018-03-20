# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import datetime
import httplib
import requests
import logging

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID
from cryptography.hazmat.primitives import hashes

from sslyze.concurrent_scanner import ConcurrentScanner, PluginRaisedExceptionScanResult
from sslyze.server_connectivity import *
from sslyze.plugins.plugin_base import PluginScanCommand
from sslyze.plugins.certificate_info_plugin import *
from sslyze.plugins.compression_plugin import *
from sslyze.plugins.fallback_scsv_plugin import *
from sslyze.plugins.http_headers_plugin import *
from sslyze.plugins.heartbleed_plugin import *
from sslyze.plugins.openssl_ccs_injection_plugin import *
from sslyze.plugins.openssl_cipher_suites_plugin import *
from sslyze.plugins.robot_plugin import *
from sslyze.plugins.session_renegotiation_plugin import *
from sslyze.plugins.session_resumption_plugin import *

from issues import IssueManager


class SSLyzeScanner:
    """
    Minimum size of public key used by certificate before raising issue  
    """
    MINIMUM_PUB_KEY_SIZE_RSA = 2048
    MINIMUM_PUB_KEY_SIZE_ECCD = 256

    # options for cipher checking
    blacklist_cipher = []
    whitelist_cipher = []
    deprecated_cipher = []
    forward_sec_cipher = []

    enforce_order = "False"
    tlds_list = []
    wildcard_level = -1

    resolve_ip = False

    check_only_custom_CA = False

    issue_manager = IssueManager()
    """:type : IssueManager
    Handler of issues for scan analysis"""

    command_list = []
    """:type : list[Type[PluginScanCommand]]
    List of command that will be executed as plugin during the scan"""

    target_list = []
    """:type : list
    List of targets to scan"""

    def _add_command(self, command_name):
        """
        Will add the given command to the scan list if not already present
        :param command_name: needed plugin command
        :type command_name : Type[PluginScanCommand]
        """
        if command_name not in self.command_list:
            self.command_list.append(command_name)

    def check_certinfo(self, ca_file=None):
        """
        Add the Certinfo plugin to the scan, with path to the custom CA if needed
        :param ca_file :    The path to a custom trust store .pem file to use for certificate validation.
        :type ca_file :     str
        """
        self._add_command(CertificateInfoScanCommand(ca_file))

    def check_heartbleed(self):
        """
        Add the Heartbleed plugin to the scan
        """
        self._add_command(HeartbleedScanCommand())

    def check_robot(self):
        """
        Add the Robot test to the scan
        :return:
        """
        self._add_command(RobotScanCommand())

    def check_session_resumption(self):
        """
        Add the Session Resumption Plugin to the scan 
        """
        self._add_command(SessionResumptionSupportScanCommand())

    def check_session_renegotiation(self):
        """
        Add the Session renegotiation Plugin to the scan 
        """
        self._add_command(SessionRenegotiationScanCommand())

    def check_scsv_fallback(self):
        """
        Add the Fallback scsv Plugin to the scan 
        """
        self._add_command(FallbackScsvScanCommand())

    def check_http_headers(self):
        """
        Add the http headers Plugin to the scan 
        """
        self._add_command(HttpHeadersScanCommand())

    def check_ssl_v2(self):
        """
        Add the ssl v2 Plugin to the scan 
        """
        self._add_command(Sslv20ScanCommand())

    def check_ssl_v3(self):
        """
        Add the ssl v3 Plugin to the scan 
        """
        self._add_command(Sslv30ScanCommand())

    def check_tls_v10(self):
        """
        Add the tls v1.0 Plugin to the scan 
        """
        self._add_command(Tlsv10ScanCommand())

    def check_tls_v11(self):
        """
        Add the tls v1.1 Plugin to the scan 
        """
        self._add_command(Tlsv11ScanCommand())

    def check_tls_v12(self):
        """
        Add the tls v1.2 Plugin to the scan 
        """
        self._add_command(Tlsv12ScanCommand())

    def check_compression(self):
        """
        Add the compression Plugin to the scan 
        """
        self._add_command(CompressionScanCommand())

    def set_blacklisted_ciphers(self, cipher_list):
        """
        Blacklisted cipher found in accepted cipher will raise an issue
        :param cipher_list: 
        :type cipher_list: list[str]
        """
        self.blacklist_cipher = cipher_list

    def set_whitelisted_ciphers(self, cipher_list):
        """
        Whitelisted cipher found in accepted cipher will not raise an issue
        :param cipher_list: 
        :type cipher_list: list[str]
        """
        self.whitelist_cipher = cipher_list

    def set_forward_sec_ciphers(self, cipher_list):
        """
        define list of cipher respecting Perfect Forward Security
        :param cipher_list: 
        :type cipher_list: list[str]
        """
        self.forward_sec_cipher = cipher_list

    def set_deprecated_ciphers(self, cipher_list):
        """
        define list of deprecated ciphers that will raise an issue
        :param cipher_list: 
        :type cipher_list: list[str]
        """
        self.deprecated_cipher = cipher_list

    def define_enforced_order(self, ordered):
        """
        Set the flag for needing preferred cipher in front position in whitelisted cipher list
        :param ordered: state of the flag
        :type ordered:  bool
        """
        self.enforce_order = ordered

    def define_willdcard_level(self, level):
        """
        set minimum level of subdomain for wildcard in the Hostname or SAN
        :param level: minimum level
        :type level: int
        """
        self.wildcard_level = level

    def set_tld_list(self, tlds):
        """
        Define list of know tlds, used for checking willcard level
        :param tlds: list of tlds used on internet
        :type tlds: list[str]
        """
        self.tlds_list = tlds

    def set_host_resolution(self, resolve):
        """
        Define if SSLyze must scans every A record for a given hostname
        :param resolve: flag
        :type resolve: bool
        """
        self.resolve_ip = resolve

    def set_only_custom_CA_validation(self, flag):
        """
        Define flag if the certificate must be checked only against the custom CA 
        and skip result from officials trust stores
        :param flag :    activate the restriction
        :type flag :    bool  
        """
        self.check_only_custom_CA = flag

    def __init__(self, targets=list()):
        self.target_list = targets

    def run(self):
        """
        Run a scan on each target defined with the defined plugin commands
        """
        # List of resolved target list[(target, ServerConnectivityInfo)]
        resolved_list = []

        # Build target for sslyze
        for target in self.target_list:
            if self.resolve_ip:
                try:
                    import dns.resolver
                    # Resolve IP for each target
                    answer = dns.resolver.query(target, 'A')

                    for ip in answer:
                        conn = ServerConnectivityInfo(hostname=target, ip_address=ip.address)
                        actual_target = "%s{%s}" % (target, ip)

                        resolved_list.append((actual_target, conn))
                except:
                    raise Exception("Cannot load dnspython library, can't resolve ip from target")
            else:
                conn = ServerConnectivityInfo(hostname=target)
                resolved_list.append((target, conn))

        # Browse targets
        for target, server_info in resolved_list:
            finger_print = None
            issuer = None

            try:
                # Check connectivity to server
                server_info.test_connectivity_to_server()

            except ServerConnectivityError as e:
                # Could not establish an SSL connection to the server
                raise RuntimeError(u'Error when connecting to {}: {}'.format(target, e.error_msg))

            # Set the issue manager
            self.issue_manager.new_target(server_info.ip_address)

            # Launch scans
            concurrent_scanner = ConcurrentScanner()

            for command in self.command_list:
                concurrent_scanner.queue_scan_command(server_info, command)

            # Process result
            for scan_result in concurrent_scanner.get_results():
                # All scan results have the corresponding scan_command and server_info as an attribute

                logging.debug(u'Received scan result for {} on host {}'.format(
                    scan_result.scan_command.__class__.__name__, scan_result.server_info.hostname))

                # TODO handle error
                # Sometimes a scan command can unexpectedly fail (as a bug);
                # it is returned as a PluginRaisedExceptionResult
                if isinstance(scan_result, PluginRaisedExceptionScanResult):
                    logging.error(u'Scan command failed: {}'.format(scan_result.as_text()))
                    #raise RuntimeError(u'Scan command failed: {}'.format(scan_result.as_text()))
                    continue

                # Check certificate validity
                if isinstance(scan_result.scan_command, CertificateInfoScanCommand):
                    (finger_print, issuer) = self._validate_certificate(scan_result, target)

                # Check sslv2
                if isinstance(scan_result.scan_command, Sslv20ScanCommand):
                    self._validate_cipher_result(scan_result, "sslv2", False)

                # Check sslv3
                if isinstance(scan_result.scan_command, Sslv30ScanCommand):
                    self._validate_cipher_result(scan_result, "sslv3", False)

                # Check TLS 1.0
                if isinstance(scan_result.scan_command, Tlsv10ScanCommand):
                    self._validate_cipher_result(scan_result, "TLS 1.0", True)

                # Check TLS 1.1
                if isinstance(scan_result.scan_command, Tlsv11ScanCommand):
                    self._validate_cipher_result(scan_result, "TLS 1.1", True)

                # Check TLS 1.2
                if isinstance(scan_result.scan_command, Tlsv12ScanCommand):
                    self._validate_cipher_result(scan_result, "TLS 1.2", True)

                # Check Compression
                if isinstance(scan_result.scan_command, CompressionScanCommand):
                    self._validate_compression(scan_result)

                # Check FallbackScsv
                if isinstance(scan_result.scan_command, FallbackScsvScanCommand):
                    self._validate_fallback_scsv(scan_result)

                # Check Heartbleed
                if isinstance(scan_result.scan_command, HeartbleedScanCommand):
                    self._validate_heartbleed(scan_result)

                # Check Http headers
                if isinstance(scan_result.scan_command, HttpHeadersScanCommand):
                    self._validate_http_headers(scan_result)

                # Check OpenSSL CCS injection vulnerability (CVE-2014-0224)
                if isinstance(scan_result.scan_command, OpenSslCcsInjectionScanCommand):
                    self._validate_openssl_ccs(scan_result)

                # Check session renegotiation
                if isinstance(scan_result.scan_command, SessionRenegotiationScanCommand):
                    self._validate_session_reneg(scan_result)

                # Check session resumption
                if isinstance(scan_result.scan_command, SessionResumptionSupportScanCommand):
                    self._validate_session_resumption(scan_result)

                # Check ROBOT vulnerability
                if isinstance(scan_result.scan_command, RobotScanCommand):
                    self._validate_robot(scan_result)

            # Check http to https redirection
            self._validate_http_redirection(target)

            # Update issuer manager with target info
            infos = {"URL": target, "IP": server_info.ip_address, "CA": finger_print, "issuer": issuer}
            self.issue_manager.add_target_info(infos)

    def generate_issues(self):
        """
        Generate issues found during previous execution of scans
        :return: list of issues
        """
        return self.issue_manager.generate_issues()

    def _validate_http_redirection(self, target, use_ip=True, retry=True):
        """
        Check if hostname redirects http to https
        :param target:  hostname with or without ip like foo.bar.io or evil.corp.ws{1.2.3.4}
        :type target:   str
        :param use_ip:  use ip specified with target for request
        :type use_ip:   bool
        :param retry:   flag to retry without ip specification, False allows to break the recursive calls
        :type retry:    bool
        """
        # Parse target for ip and hostname
        parsed = target.split("{")
        host = parsed[0]
        ip = None
        if len(parsed) > 1 and use_ip:
            # Remove trailing }
            ip = parsed[1][:-1]
        else:
            ip = host

        # Add the scheme wanted by request
        url = "http://{ip}".format(ip=ip)

        # Build request (request will follow redirection until final destination reached)
        try:
            if use_ip:
                response = requests.get(url, headers={'Host': host})
            else:
                response = requests.get(url)

            code = response.status_code

            # Check if there has been a redirection
            if response.history:
                # Check the original redirection url
                fr = response.history[0]
                fr_loc = fr.headers.get("Location")

                if fr_loc.startswith("https://"):
                    logging.info("Received redirection from HTTP to HTTPS : {code} - {loc}".
                                 format(code=code, loc=fr_loc))
                else:
                    # FIXME raise an issue if the first redirect was not to https
                    # Check if the last redirection is https even if the first was not
                    location = response.url
                    if location.startswith("https://"):
                        logging.info("The first redirection was not to HTTPS but to {fr_loc}\n"
                                     "Then it received a redirect to HTTPS : {code} - {loc}".
                                     format(fr_loc=fr_loc, code=code, loc=location))
                        self.issue_manager.no_http_redirect(code, final_https=True, final_destination=location,
                                                            location=fr_loc)
                    else:
                        # fail
                        self.issue_manager.no_http_redirect(code, location)
                        logging.info("Did not redirect HTTP to HTTPS : {code} - {loc}".format(code=code, loc=location))
            # Case no redirect
            else:
                # fail
                self.issue_manager.no_http_redirect(code, location=response.reason)
                logging.info("Did not redirect HTTP to HTTPS : {code}".format(code=code))
        except requests.exceptions.TooManyRedirects as e:
            # Break if inside recursive loop
            if not retry:
                raise e

            # Retry without ip resolution bypass
            try:
                self._validate_http_redirection(target, use_ip=False, retry=False)
            except:
                # Use old method
                h = httplib.HTTPConnection(ip)
                h.request('GET', '/', headers={'host': host})
                response = h.getresponse()

                # Check if there is a redirection
                code = response.status
                if code in [301, 302]:
                    # Check the location contains https redirect
                    location = response.getheader('Location')
                    if location.startswith("https://"):
                        logging.info("Received redirection from HTTP to HTTPS : {code} - {loc}".format(code=code, loc=location))
                    else:
                        # fail
                        self.issue_manager.no_http_redirect(code, location=location)
                        logging.info("Did not redirect HTTP to HTTPS : {code} - {loc}".format(code=code, loc=location))
                else:
                    # fail
                    self.issue_manager.no_http_redirect(code, location=response.reason)
                    logging.info("Did not redirect HTTP to HTTPS : {code}".format(code=code))
        except Exception as e:
            logging.warning("Could not request {target}, {message}".format(target=target, message=e.message))

    def _validate_certificate(self, scan_result, hostname):
        """
        Run all needed test and analysis regarding certificate
        :param scan_result: result of the CertificateInfoScanCommand
        :type scan_result: CertificateInfoScanResult
        :param hostname:   host used to connect to target
        :type hostname: str
        :return tuple containing certificate hash and the authority signing it
        :rtype (str,str)
        """
        for line in scan_result.as_text():
            logging.info(line)

        # Get the leaf certificate
        cert = scan_result.certificate_chain[0]

        # TODO handle other formats
        from cryptography.hazmat.primitives.asymmetric import rsa
        pub_key = cert.public_key()

        # Check size of certificate public key
        if pub_key.key_size < self.MINIMUM_PUB_KEY_SIZE_RSA:
            self.issue_manager.no_ats_valid({"pub_key_size": str(pub_key.key_size), "pub_key_algo": "RSA"})
            self.issue_manager.low_key_size(self.MINIMUM_PUB_KEY_SIZE_RSA, str(pub_key.key_size))

        # Check certificate lifetime
        today = datetime.datetime.today()

        # Check certificate expired
        if cert.not_valid_after < today:
            self.issue_manager.certificate_expired(unicode(cert.not_valid_after.replace(microsecond=0)),
                                                   unicode(today.replace(microsecond=0)))
        # Check certificate not valid yet
        if cert.not_valid_before > today:
            self.issue_manager.certificate_not_valid_yet(unicode(cert.not_valid_after.replace(microsecond=0)),
                                                         unicode(today.replace(microsecond=0)))

        # Get issuer
        issuer = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        # Get sha1 Fingerprint
        sha1_fingerprint = cert.fingerprint(hashes.SHA1()).encode("hex")

        # Get common name
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        # Get subject alt name
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_list = ext.value.get_values_for_type(x509.DNSName)
        except Exception as e:
            logging.error("Could not find Subject Alt Name for certificate : {err}".format(err=e.message))
            san_list = []

        # Add the common name if missing
        # TODO raise an issue
        if cn not in san_list:
            san_list.append(cn)

        # Check wildcard for CommonName and AlternativeNames
        self._check_wildcard(san_list)

        # Certificate hostname validation
        if not scan_result.certificate_matches_hostname:
            self.issue_manager.no_hostname_validation(hostname, san_list)

        # Check if the certificate chain is in the correct order
        if not scan_result.is_certificate_chain_order_valid:
            self.issue_manager.wrong_chain_order()

        # Check if the certificate is signed with sha1 or present in intermediate chain
        if scan_result.has_sha1_in_certificate_chain:
            self.issue_manager.signed_with_sha1()
            self.issue_manager.no_ats_valid({"sha1": True})
        # Perform additional checks on sha1 while it's not integrated in sslyze
        # Check as a fallback if the certificate is trusted but the certificate chain is incorrect
        elif scan_result.successful_trust_store and not scan_result.is_certificate_chain_order_valid:
            for cert in scan_result.certificate_chain:
                if isinstance(cert.signature_hash_algorithm, hashes.SHA1):
                    # Check if certificate is a root certificate that is alloyed to have SHA1 signing
                    if scan_result.successful_trust_store._get_certificate_with_subject(cert.subject):
                        continue
                    else:
                        self.issue_manager.signed_with_sha1()
                        self.issue_manager.no_ats_valid({"sha1": True})
                        break
        # As a fallback, just check the leaf certificate (still better than nothing)
        else:
            cert = scan_result.certificate_chain[0]
            if isinstance(cert.signature_hash_algorithm, hashes.SHA1):
                self.issue_manager.signed_with_sha1()
                self.issue_manager.no_ats_valid({"sha1": True})

        # Check CA validation
        # FIXME handle case only result of custom CA matters
        if not scan_result.successful_trust_store:
            text_error = ""
            for result in scan_result.path_validation_result_list:
                # Get error info from failed trust store
                if not result.is_certificate_trusted:
                    # Only take result from custom CA if needed
                    if (self.check_only_custom_CA and result.trust_store.name == "Custom --ca_file") \
                            or not self.check_only_custom_CA:
                        text_error = "{curr}<br>{name} : {error}".\
                            format(curr=text_error, name=result.trust_store.name, error=result.verify_string)

            self.issue_manager.certificate_not_valid(text_error)

        return sha1_fingerprint, issuer

    def _validate_cipher_result(self, scan_result, version, alloyed, need_fs=False, version_needed=False):
        """
        Main method to analyse and validate a SSL or TLS Scan Command
        :param scan_result : result of the plugin
        :type scan_result  : CipherSuiteScanResult
        :param version : name of the ssl or tls being tested
        :type version  : str 
        :param alloyed : flag if the ssl or tls can accepted ciphers
        :type alloyed  : bool
        :param need_fs : describe if the tested version need to have one cipher supporting Forward Secrecy
        :type need_fs  : bool
        :param version_needed   : will raise an issue if no cipher is accepted for this version
        :type version_needed    : bool
        """
        # Get accepted cipher
        accepted_ciphers = []
        for cipher in scan_result.accepted_cipher_list:
            accepted_ciphers.append(cipher.name)

        try:
            preferred_cipher = scan_result.preferred_cipher.name
        except AttributeError:
            preferred_cipher = None

        # Check the version is not alloyed but active
        if (accepted_ciphers or preferred_cipher) and not alloyed:
            if version == "sslv2":
                self.issue_manager.support_sslv2(preferred_cipher, accepted_ciphers)
            elif version == "sslv3":
                self.issue_manager.support_sslv3(preferred_cipher, accepted_ciphers)
            else:
                # FIXME be generic
                pass
            return

        # Check if tls 1.2 is not supported
        # FIXME be generic
        if not (accepted_ciphers or preferred_cipher) and version_needed and version == "TLS 1.2":
            self.issue_manager.no_tls_v1_2()
            self.issue_manager.no_ats_valid({"support_tls_v1_2": False})

        # Filter accepted ciphers
        self._filter_cipher(accepted_ciphers, version, need_fs)

        # Check if preferred cipher must be first in accepted from cipher list
        if self.enforce_order:
            self._check_cipher_order(accepted_ciphers, preferred_cipher, version)

    def _validate_compression(self, scan_result):
        """
        Check the result for Zlib compression support.
        :param scan_result : result of the plugin
        :type scan_result  : CompressionScanResult
        """
        for line in scan_result.as_text():
            logging.info(line)

        # Check if a compression method is used
        if scan_result.compression_name:
            self.issue_manager.insecure_compression([scan_result.compression_name])

    def _validate_fallback_scsv(self, scan_result):
        """
        Check the result for support of the TLS_FALLBACK_SCSV cipher suite which prevents downgrade attacks.
        :param scan_result : result of the plugin
        :type scan_result  : FallbackScsvScanResult
        """
        for line in scan_result.as_text():
            logging.info(line)

        if not scan_result.supports_fallback_scsv:
            # FIXME raise issue
            pass

    def _validate_heartbleed(self, scan_result):
        """
        Check the result for existence of OpenSSL Heartbleed vulnerability.
        :param scan_result : result of the plugin
        :type scan_result  : HeartbleedScanResult
        """
        for line in scan_result.as_text():
            logging.info(line)

        if scan_result.is_vulnerable_to_heartbleed:
            self.issue_manager.heartbleed()

    def _validate_http_headers(self, scan_result):
        """
        Check results for the HTTP Strict Transport Security (HSTS) and HTTP Public Key Pinning (HPKP) HTTP headers
        :param scan_result  : result of the plugin
        :type scan_result   : HttpHeadersScanResult
        """
        for line in scan_result.as_text():
            logging.info(line)

        # Check for presence of ParsedHstsHeader
        if not scan_result.hsts_header:
            self.issue_manager.no_hsts()

        # TODO implement hpkp verification

    def _validate_openssl_ccs(self, scan_result):
        """
        Check results for the OpenSSL CCS injection vulnerability (CVE-2014-0224)
        :param scan_result  : result of the plugin
        :type scan_result   : OpenSslCcsInjectionScanResult
        """
        for line in scan_result.as_text():
            logging.info(line)

        if scan_result.is_vulnerable_to_ccs_injection:
            # TODO implement issue for OpenSSL CCS injection vulnerability (CVE-2014-0224)
            pass

    def _validate_session_reneg(self, scan_result):
        """
        Check results for client-initiated renegotiation and secure renegotiation support.
        :param scan_result  : result of the plugin 
        :type scan_result   : SessionRenegotiationScanResult
        """
        for line in scan_result.as_text():
            logging.info(line)

        if scan_result.accepts_client_renegotiation:
            self.issue_manager.client_renegotiation()

        if not scan_result.supports_secure_renegotiation:
            self.issue_manager.secure_renegotiation()

    def _validate_session_resumption(self, scan_result):
        """
        Check results for session resumption support using session IDs and TLS session tickets (RFC 5077).
        :param scan_result  : result of the plugin 
        :type scan_result   : SessionResumptionSupportScanResult
        """
        for line in scan_result.as_text():
            logging.info(line)

        # Check session resumption results.
        # From what I read from the plugin's code, it fails if not every attempt is successful
        # TODO give more info about result
        if not scan_result.attempted_resumptions_nb != scan_result.successful_resumptions_nb:
            self.issue_manager.session_resumption_id()

        if not scan_result.is_ticket_resumption_supported:
            self.issue_manager.session_resumption_ticket()

    def _validate_robot(self, scan_result):
        """
        Check ROBOT vulnerability result
        :param scan_result:     result of the plugin
        :type scan_result:      RobotScanResult
        """
        for line in scan_result.as_text():
            logging.info(line)

        # Check result value :
        res = scan_result.robot_result_enum

        if res == RobotScanResultEnum.VULNERABLE_WEAK_ORACLE:
            # Raise issue
            self.issue_manager.robot_vulnerability("The server is vulnerable but the attack would take too long")
        elif res == RobotScanResultEnum.VULNERABLE_STRONG_ORACLE:
            # Raise issue
            self.issue_manager.robot_vulnerability("The server is vulnerable and real attacks are feasible")
        elif res in (RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE, RobotScanResultEnum.NOT_VULNERABLE_RSA_NOT_SUPPORTED):
            # Info not vulnerable
            logging.info("Not vulnerable to ROBOT vulnerability")
        elif res == RobotScanResultEnum.UNKNOWN_INCONSISTENT_RESULTS:
            logging.info("Inconsistent results found")

    def _filter_cipher(self, accepted_ciphers, version, need_fs=False):
        """
        Browse accepted ciphers and check whether they are blacklisted or whitelisted
        :param accepted_ciphers : list of accepted ciphers
        :type accepted_ciphers  : list[str]
        :param version:  name of the version assessed like "TLS 1.2"
        :param need_fs: 
        """
        blacklisted = ""
        not_whitelisted = ""
        deprecated = ""

        fs_counter = 0

        # Browse the cipher list
        for cipher in accepted_ciphers:
            # Check if the cipher is not whitelisted
            if cipher not in self.whitelist_cipher:
                # Check if the cipher contains blacklisted term
                if any(bl_c in cipher for bl_c in self.blacklist_cipher):
                    # Add cipher to blacklist issue
                    if not blacklisted:
                        blacklisted += cipher
                    else:
                        blacklisted += ", " + cipher
                else:
                    # Add the cipher to unauthorized list
                    if not not_whitelisted:
                        not_whitelisted += cipher
                    else:
                        not_whitelisted += ", " + cipher

            # Check if the cipher is deprecated
            if any(dp_c in cipher for dp_c in self.deprecated_cipher):
                # Add the cipher to deprecated list
                if not deprecated:
                    deprecated += cipher
                else:
                    deprecated += ", " + cipher

            # Check if at least one filter supports Forward Secrecy
            if any(dp_c in cipher for dp_c in self.forward_sec_cipher):
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
        if fs_counter == 0 and need_fs:
            self.issue_manager.no_ats_valid({"support_fs": False})

    def _check_cipher_order(self, accepted_ciphers, preferred_cipher, version):
        """
        Check if the preferred cipher is the most secure accepted cipher, 
        preferred cipher must be first in accepted from cipher list
        :param accepted_ciphers : list of accepted cipher by the connexion version
        :type accepted_ciphers  : list[str]
        :param preferred_cipher: preferred cipher by the connexion version
        :type preferred_cipher : str
        :param version  : name of the version assessed like "tls V1.2"
        :type version   : str
        :return: 
        """

        # get index of preferred cipher
        try:
            pref_id = self.whitelist_cipher.index(preferred_cipher)
        except Exception:
            pref_id = len(self.whitelist_cipher) + 1

        safer_cipher_id = pref_id
        safer_cipher = ""

        # Browse the ciphers list to find the most secure accepted cipher (best is the first of the white-list)
        for cipher in accepted_ciphers:
            # get index of accepted cipher
            if cipher in self.whitelist_cipher:
                acc_id = self.whitelist_cipher.index(cipher)
            else:
                continue

            # Check that no other accepted cipher has a lower index
            if acc_id < safer_cipher_id:
                safer_cipher_id = acc_id
                safer_cipher = cipher

        # Check if the preferred cipher is the best cipher from accepted regarding the white-list
        if safer_cipher_id < pref_id:
            self.issue_manager.no_cipher_order(version, safer_cipher, preferred_cipher)

    def _check_wildcard(self, urls):
        """
        Checks the validity of wildcard usage
        :param urls : array containing address or commonName or AlternativeName to check
        :type urls : list[str] 
        """
        mixed_wildcard = []
        bad_level_wildcard = []

        for url in urls:
            # Check if url contains a wildcard
            if "*" not in url:
                continue

            # Remove the protocol from the url if any
            url = url.replace("https://", "")
            url = url.replace("http://", "")

            url_elements = url.split('.')   # structure is url_elements = ["abcde","co","uk"]

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

                if candidate in self.tlds_list:
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

    if __name__ == "__main__":
        pass


