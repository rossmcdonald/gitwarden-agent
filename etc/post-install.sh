#!/bin/bash
#
# Author: Ross McDonald (ross.mcdonald@gitwarden.com)
# Copyright 2017, Summonry Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# For usage information, simply run `make` from the root directory of
# the gitwarden-agent repository.
#
# For bugs or feature requests, please file an issue against the GitWarden Agent
# repository on Github at:
#
# https://github.com/gitwarden/gitwarden-agent
#

# Create data directory, if not already present
test -d /var/lib/gitwarden || mkdir -p /var/lib/gitwarden

# Touch data file, if not already present
test -f /var/lib/gitwarden/gitwarden-data.yml || touch /var/lib/gitwarden/gitwarden-data.yml

if [[ "$(readlink /proc/1/exe)" == */systemd ]]; then
    # systemd systems
    cp -f /usr/lib/gitwarden/gitwarden-agent.service /etc/systemd/system/gitwarden-agent.service
    systemctl enable gitwarden-agent || true
    systemctl daemon-reload || true
else
    # sysv systems
    cp -f /usr/lib/gitwarden/gitwarden-agent.init /etc/init.d/gitwarden-agent
    chmod +x /etc/init.d/gitwarden-agent

    which update-rc.d &>/dev/null && update-rc.d gitwarden-agent defaults
    which chkconfig &>/dev/null && chkconfig --add gitwarden-agent
fi

exit 0
