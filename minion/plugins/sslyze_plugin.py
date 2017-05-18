# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
import os
import uuid
import socket
from urlparse import urlparse
from minion.plugins.base import BlockingPlugin


from scanner import Scanner


class SSLyzePlugin(BlockingPlugin):
    PLUGIN_NAME = "SSlyze"
    PLUGIN_VERSION = "1.1.0"
    PLUGIN_WEIGHT = "light"

    SSLyze_NAME = "sslyze"

    # Instantiation of output
    report_dir = "/tmp/artifacts/"
    output_id = str(uuid.uuid4())
    schedule_stderr = ""
    logger = None
    logger_path = ""

    scanner = Scanner()

    def initialize_logger(self):
        """
        Initialize the logger used by the plugin
        """

        # create logger
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.DEBUG)

        # create console handler and set level to debug
        ch = logging.FileHandler(self.logger_path)
        ch.setLevel(logging.DEBUG)

        # create formatter
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        # add formatter to ch
        ch.setFormatter(formatter)

        # add ch to logger
        self.logger.addHandler(ch)

        # self.logger.debug('debug message')
        # self.logger.info('info message')
        # self.logger.warn('warn message')
        # self.logger.error('error message')
        # self.logger.critical('critical message')

    def _check_options(self):
        # General
        if "timeout" in self.configuration:
            # args += ["--timeout", str(self.configuration["timeout"])]
            self.logger.info("Timeout is not implemented for the moment")
        if "nb_retries" in self.configuration:
            # args += ["--nb_retries", str(self.configuration["nb_retries"])]
            self.logger.info("nb_retries is not implemented for the moment")
        if "https_tunnel" in self.configuration:
            # args += ["--https_tunnel", self.configuration["https_tunnel"]]
            self.logger.info("https_tunnel is not implemented for the moment")
        if "starttls" in self.configuration:
            # args += ["--starttls", self.configuration["starttls"]]
            self.logger.info("starttls is not implemented for the moment")
        if "xmpp_to" in self.configuration:
            # args += ["--xmpp_to", self.configuration["xmlpp_to"]]
            self.logger.info("xmpp_to is not implemented for the moment")
        if "sni" in self.configuration:
            # args += ["--sni", self.configuration["sni"]]
            self.logger.info("sni is not implemented for the moment")
        if "regular" in self.configuration:
            # args += ["--regular"]
            self.logger.info("regular is not implemented for the moment")

        # Client certificate support
        if "cert" in self.configuration:
            # args += ["--cert", self.configuration["cert"]]
            self.logger.info("cert is not implemented for the moment")
        if "certform" in self.configuration:
            # args += ["--certform", self.configuration["certform"]]
            self.logger.info("certforms is not implemented for the moment")
        if "key" in self.configuration:
            # args += ["--key", self.configuration["key"]]
            self.logger.info("key is not implemented for the moment")
        if "keyform" in self.configuration:
            # args += ["--keyform", self.configuration["keyform"]]
            self.logger.info("keyform is not implemented for the moment")
        if "pass" in self.configuration:
            # args += ["--pass", self.configuration["pass"]]
            self.logger.info("pass is not implemented for the moment")

        # PluginCertInfo
        if "certinfo" in self.configuration and self.configuration["certinfo"]:
            # Add External --ca_file if needed
            if "ca_file" in self.configuration:
                self.scanner.check_certinfo(self.configuration["ca_file"])
            else:
                self.scanner.check_certinfo()

        # PluginHeartbleed
        if "heartbleed" in self.configuration:
            self.scanner.check_heartbleed()

        # PluginSessionResumption
        if "resum" in self.configuration:
            self.scanner.check_session_resumption()
        if "resum_rate" in self.configuration:
            # args += ["--resum_rate"]
            self.logger.info("resum_rate is not implemented for the moment")

        # PluginOpenSSLCipherSuite
        if "sslv2" in self.configuration:
            self.scanner.check_ssl_v2()
        if "sslv3" in self.configuration:
            self.scanner.check_ssl_v3()
        if "tlsv1" in self.configuration:
            self.scanner.check_tls_v10()
        if "tlsv1_1" in self.configuration:
            self.scanner.check_tls_v11()
        if "tlsv1_2" in self.configuration:
            self.scanner.check_tls_v12()

        if "http_get" in self.configuration:
            # args += ["--http_get"]
            self.logger.info("http_get is not implemented for the moment")
        if "hide_rejected_ciphers" in self.configuration:
            # args += ["--hide_rejected_ciphers"]
            self.logger.info("hide_rejected is not implemented for the moment")

        # PluginCompression
        if "compression" in self.configuration:
            self.scanner.check_compression()

        # PluginSessionRenegotation
        if "reneg" in self.configuration:
            self.scanner.check_session_renegotiation()

        # PluginHSTS
        if "hsts" in self.configuration:
            self.scanner.check_http_headers()

        # Plugin FallbackScsv
        if "scsv" in self.configuration:
            self.scanner.check_scsv_fallback()

    def set_data(self):

        if "blacklist_cipher" in self.configuration:
            self.scanner.set_blacklisted_ciphers(self.configuration["blacklist_cipher"].split(':'))

        if "whitelist_cipher" in self.configuration:
            self.scanner.set_whitelisted_ciphers(self.configuration["whitelist_cipher"].split(':'))

        if "forward_sec_cipher" in self.configuration:
            self.scanner.set_forward_sec_ciphers(self.configuration["forward_sec_cipher"].split(':'))

        if "enforce_order" in self.configuration:
            self.scanner.define_enforced_order(self.configuration["enforce_order"])

        if "deprecated" in self.configuration:
            self.scanner.set_deprecated_ciphers(self.configuration["deprecated"].split(':'))

        if "wildcard_level" in self.configuration:
            self.scanner.define_willdcard_level(int(self.configuration["wildcard_level"]))

            if "tld_path" in self.configuration:
                with open(self.configuration["tld_path"]) as tld_file:
                    self.scanner.set_tld_list([line.strip() for line in tld_file if line[0] not in "/\n"])

        if "only_custom_CA" in self.configuration:
            self.scanner.set_only_custom_CA_validation(self.configuration["only_custom_CA"])

        # Check if SSLyze must scan every A record for given hostname
        if "resolve_ip" in self.configuration:
            self.scanner.set_host_resolution(self.configuration["resolve_ip"])

        if 'report_dir' in self.configuration:
            self.report_dir = self.configuration['report_dir']

    def do_run(self):

        url = urlparse(self.configuration['target'])
        target = url.hostname

        # Check if the target is an ip to avoid empty hostname
        if not target:
            target = url.path

        # Build the scanner
        self.scanner = Scanner([target])

        # Set constants data
        self.set_data()

        # Apply parameters from config
        self._check_options()

        # Run actual scan against targets
        self.scanner.run()

        # Retrieve results TODO handle failure
        issues = self.scanner.generate_issues()

        # Report issues to minion
        self.report_issues(issues)

        # Save logs
        self._save_artifacts()

        # Exit
        return

    def do_process_ended(self, status):
        if self.stopping and status == 9:
            self.report_finish("STOPPED")
        elif status == 0:
            self.parse_sslyze_output(self.xml_output)

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