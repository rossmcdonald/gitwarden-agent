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

function err {
    printf "[\e[31mERROR\e[39m] $@\n"
    exit 1
}

function init {
    echo '        _ __ _      __            __
  ___ _(_) /| | /| / /__ ________/ /__ ___
 / _ `/ / __/ |/ |/ / _ `/ __/ _  / -_) _ \
 \_, /_/\__/|__/|__/\_,_/_/  \_,_/\__/_//_/
/___/     Linux user management, simplified
'
    which curl &>/dev/null \
        || err "The program 'curl' is required. Please install 'curl' and rerun."
}

function install_apt {
    echo "Importing the GitWarden packaging key..."
    curl -sL https://archives.gitwarden.com/gitwarden.key | sudo apt-key add - &>/dev/null
    if [[ $? -ne 0 ]]; then
        err "Encountered error when importing GitWarden GPG key"
    fi

    echo "Adding the GitWarden package repository to the local apt configuration"
    if [[ ! -f /etc/apt/sources.list.d/gitwarden.list ]]; then
        echo "deb https://archives.gitwarden.com/deb squeeze main" | sudo tee /etc/apt/sources.list.d/gitwarden.list &>/dev/null
        if [[ $? -ne 0 ]]; then
            err "Encountered error when importing writing repository configuration to /etc/apt/sources.list.d/gitwarden.list"
        fi
    fi

    echo "Updating apt package database..."
    apt-get update &>/dev/null

    echo "Installing agent..."
    apt-get install -y gitwarden-agent &>/dev/null
    if [[ $? -ne 0 ]]; then
        err "Encountered error when installing the gitwarden-agent package"
    fi
}

function install_yum_dnf {
    if [[ ! -f /etc/yum.repos.d/gitwarden.repo ]]; then
        echo "Adding the GitWarden package repository to the local yum/dnf configuration"
        cat <<EOF | sudo tee /etc/yum.repos.d/gitwarden.repo
[gitwarden  ]
name=GitWarden Package Repository
baseurl=https://archives.gitwarden.com/rpm
enabled=1
gpgcheck=1
gpgkey=https://archives.gitwarden.com/gitwarden.key
EOF
    else
        echo "GitWarden repository entry already present..."
    fi

    echo "Installing agent..."
    which dnf &>/dev/null
    if [[ $? -eq 0 ]]; then
        dnf install -y gitwarden-agent &>/dev/null
    else
        yum install -y gitwarden-agent &>/dev/null
    fi
    if [[ $? -ne 0 ]]; then
        err "Encountered error when installing the gitwarden-agent package"
    fi
}

function install_zypper {
    err "Sorry, GitWarden does not yet support SLES/OpenSUSE systems. Please contact support@gitwarden.com for any further information."
}

function configure {
    # test -z "$KEY" && err "No KEY environment variable provided, stopping here."
    # test -z "$SECRET" && err "No SECRET environment variable provided, stopping here."
    # test -z "$TEAMS" && err "No TEAMS provided, stopping here."
    # test -z "$ADMIN_TEAMS" && err "No TEAMS provided, stopping here."

    echo $TEAMS
    array=()
    while IFS=, read -r col1 coln
    do
        array+=("$col1") # append $col1 to array array
    done < <( $TEAMS | tail )

    declare -p array
    echo "GOT ARRAY: ${array[@]}"
}

function main {
    init
    configure
    exit 0

    which apt-get &>/dev/null
    if [[ $? -eq 0 ]]; then
        install_apt
        configure
        return
    fi

    which yum &>/dev/null
    if [[ $? -eq 0 ]]; then
        install_yum_dnf
        configure
        return
    fi

    which dnf &>/dev/null
    if [[ $? -eq 0 ]]; then
        install_yum_dnf
        configure
        return
    fi

    which zypper &>/dev/null
    if [[ $? -eq 0 ]]; then
        install_zypper
        return
    fi

    err "Sorry, GitWarden is not currently supported on your platform or distribution. Please contact support@gitwarden.com for any further information."
}

main
