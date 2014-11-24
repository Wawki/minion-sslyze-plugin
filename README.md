Minion SSLyze Plugin
====================

[![Build Status](https://drone.io/github.com/Wawki/minion-sslyze-plugin/status.png)](https://drone.io/github.com/Wawki/minion-sslyze-plugin/latest)

This project contains the code for the Minion SSLyze Plugin. It provides a plugin to Minion that executes the SSLyze tool.

Inspired from the NMAP plugin (https://github.com/mozilla/minion-nmap-plugin)

Installation
------------

It assumes that you have already Minion installed (https://github.com/mozilla/minion)

First install the SSLyze tool :

- Download at https://github.com/nabla-c0d3/sslyze/releases
- Install it by running :
    ```sudo python setup.py install```

Then run in the minion-sslyze-plugin directory : ```python setup.py install```

Example of plan
---------------

```
[
  {
    "configuration": {
      "regular": "",
      "list_exp_ciphers": "EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA:EXP-ADH-DES-CBC-SHA:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:EXP-ADH-RC4-MD5:EXP-RC4-MD5",
      "list_adh_ciphers": "ADH-AES256-GCM-SHA384:ADH-AES256-SHA256:ADH-AES256-SHA:ADH-CAMELLIA256-SHA:ADH-DES-CBC3-SHA:ADH-AES128-GCM-SHA256:ADH-AES128-SHA256:ADH-AES128-SHA:ADH-SEED-SHA:ADH-CAMELLIA128-SHA:ADH-RC4-MD5:ADH-DES-CBC-SHA:EXP-ADH-DES-CBC-SHA:EXP-ADH-RC4-MD5",
      "list_null_ciphers": "ECDHE-RSA-NULL-SHA:ECDHE-ECDSA-NULL-SHA:AECDH-NULL-SHA:ECDH-RSA-NULL-SHA:ECDH-ECDSA-NULL-SHA:NULL-SHA256:NULL-SHA:NULL-MD5"
      "list_low_ciphers": "EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:ADH-DES-CBC-SHA:DES-CBC-SHA"
    },
    "description": "",
    "plugin_name": "minion.plugins.sslyze.SSLyzePlugin"
  }
]
```

The list of weak ciphers can be generated with openssl with the following commands :

- ```openssl cipehrs EXP```
- ```openssl ciphers ADH```
- ```openssl ciphers NULL```
- ```openssl ciphers LOW```
