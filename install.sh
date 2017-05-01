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
    which test &>/dev/null || err "The program 'which' is required. Please install 'which' and rerun."
    which curl &>/dev/null || err "The program 'curl' is required. Please install 'curl' and rerun."
}

function install_apt {
    which gitwarden-agent &>/dev/null && return

    echo "Importing the GitWarden packaging key..."
    curl -sL https://archives.gitwarden.com/gitwarden.key | apt-key add - &>/dev/null
    if [[ $? -ne 0 ]]; then
        err "Encountered error when importing GitWarden GPG key"
    fi

    echo "Adding the GitWarden package repository to the local apt configuration..."
    if [[ ! -f /etc/apt/sources.list.d/gitwarden.list ]]; then
        echo "deb https://archives.gitwarden.com/deb squeeze main" | tee /etc/apt/sources.list.d/gitwarden.list &>/dev/null
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
    which gitwarden-agent &>/dev/null && return

    if [[ ! -f /etc/yum.repos.d/gitwarden.repo ]]; then
        echo "Adding the GitWarden package repository to the local yum/dnf configuration..."
        cat <<EOF | tee /etc/yum.repos.d/gitwarden.repo &>/dev/null
[gitwarden]
name=GitWarden Package Repository
baseurl=https://archives.gitwarden.com/rpm
enabled=1
gpgcheck=1
repo_gpgcheck=1
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
    test -z "$KEY" && err "No KEY environment variable provided, stopping."
    test -z "$SECRET" && err "No SECRET environment variable provided, stopping."
    test -z "$TEAMS" && err "No TEAMS provided, stopping."
    # test -z "$ADMIN_TEAMS" && err "No TEAMS provided, stopping."

    # Retain config data as string
    config="api_key: $KEY"

    # Check to see whether commas or present (meaning more than one team is
    # specified)
    commas="false"
    config="$config\n\nteams:"
    for c in $(echo $TEAMS | sed -e 's/\(.\)/\1\n/g'); do
        if [[ "$c" = "," ]]; then
            commas="true"
        fi
    done

    if [[ $commas = "true" ]]; then
        # If commas are present, parse each item
        index=1
        while [[ true ]]; do
            team=$(echo $TEAMS | cut -d, -f$index)
            index=$(($index+1))
            test -z "$team" && break
            config="$config\n  - $team"
        done
    else
        # No commas, just use the whole thing
        config="$config\n  - $TEAMS"
    fi

    if [[ ! -z "$ADMIN_TEAMS" ]]; then
        commas="false"
        config="$config\n\nadmin_teams:"
        for c in $(echo $ADMIN_TEAMS | sed -e 's/\(.\)/\1\n/g'); do
            if [[ "$c" = "," ]]; then
                commas="true"
            fi
        done

        if [[ $commas = "true" ]]; then
            index=1
            while [[ true ]]; do
                team=$(echo $ADMIN_TEAMS | cut -d, -f$index)
                index=$(($index+1))
                test -z "$team" && break
                config="$config\n  - $team"
            done
        else
            echo "TEST"
            config="$config\n  - $ADMIN_TEAMS"
        fi
    fi

    config="$config\n"
    test -d /etc/gitwarden || mkdir -p /etc/gitwarden
    printf "$config" > /etc/gitwarden/gitwarden.yml
    echo "Configuration generated and persisted to: /etc/gitwarden/gitwarden.yml"

    echo "Registering with the GitWarden service..."
    GITWARDEN_API_SECRET=$SECRET gitwarden-agent register &>/dev/null
    if [[ $? -ne 0 ]]; then
        err "Encountered error on registration. Please run 'GITWARDEN_API_SECRET=YOURSECRET gitwarden-agent register' for more information."
    fi

    echo "Registration successful! Starting service..."
    service_started="false"
    if [[ "$(readlink /proc/1/exe)" == */systemd ]]; then
        systemctl restart gitwarden-agent &>/dev/null
        if [[ $? -ne 0 ]]; then
            err "Could not start gitwarden-agent service. Please run 'systemctl restart gitwarden-agent' for more information."
        fi
        service_started="true"
    else
        /etc/init.d/gitwarden-agent restart &>/dev/null
        if [[ $? -ne 0 ]]; then
            err "Could not start gitwarden-agent service. Please run 'service gitwarden-agent restart' for more information."
        fi
        service_started="true"
    fi

    if [[ $service_started = "false" ]]; then
        err "Could not determine method for starting service. You will need to start the service manually."
        exit 0
    fi

    echo "GitWarden is now active."
}

function main {
    init

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

