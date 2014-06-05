# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from setuptools import setup

install_requires = [
    'minion-backend'
]

setup(name="minion-sslyze-plugin",
      version="0.1",
      description="SSlyze Plugin for Minion",
      url="https://github.com/Wawki/minion-sslyze-plugin/",
      author="Frederic Guegan",
      author_email="guegan.frederic@gmail.com",
      packages=['minion', 'minion.plugins'],
      namespace_packages=['minion', 'minion.plugins'],
      include_package_data=True,
      install_requires = install_requires)
