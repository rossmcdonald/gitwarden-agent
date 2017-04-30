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

function err {
    printf "[\e[31mERROR\e[39m] $@\n"
    exit 1
}

which fpm &>/dev/null || err "FPM needs to be installed before continuing"

# Create a temporary directory for build artifacts
tmpdir="$(mktemp -d)"
echo "Using temp dir: $tmpdir"

# Create directory structure under temp dir
dirs=( "/usr/sbin" "/etc/gitwarden" "/usr/lib/gitwarden" "/var/lib/gitwarden" )
for dir in ${dirs[@]}; do
    mkdir -p $tmpdir/$dir
done

# Copy files to package directory structure
cp gitwarden-agent $tmpdir/usr/sbin
cp etc/config-sample.yml $tmpdir/etc/gitwarden/gitwarden.yml
cp etc/gitwarden-agent.init $tmpdir/usr/lib/gitwarden/
cp etc/gitwarden-agent.service $tmpdir/usr/lib/gitwarden/

version=$(git describe --always --tags --abbrev=0 | tr -d 'v')

package_types=( "deb" "rpm" )
for t in ${package_types[@]}; do
    echo "Generating package type: $t"
    fpm -f -s dir -t $t \
        -v "$version" \
        -n "gitwarden-agent" \
        --vendor "SummonryLabs LLC" \
        --url "https://github.com/gitwarden/gitwarden-agent" \
        --license "apache2" \
        --maintainer "support@gitwarden.com" \
        --description "Linux user management agent, used for communicating with the GitWarden registry" \
        --config-files "/etc/gitwarden" \
        --provides "gitwarden-agent" \
        --directories "/etc/gitwarden" \
        --directories "/usr/lib/gitwarden" \
        --directories "/var/lib/gitwarden" \
        --iteration 1 \
        --after-install "etc/post-install.sh" \
        --after-remove "etc/post-uninstall.sh" \
        -C "$tmpdir" \
        -p "$(pwd)"
done
