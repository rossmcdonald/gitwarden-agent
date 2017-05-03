# gitwarden-agent

The `gitwarden-agent` is a Linux user management daemon, used for communicating with the GitWarden registry and syncing Github team changes to the local system. 

You can find more information regarding the GitWarden service [here](https://gitwarden.com).

### Installation

The easiest method for installing the agent is to run the following command from any instance that you need bootstrapped:

```sh
curl -sL https://archives.gitwarden.com/install.sh | \
  KEY=MYAPIKEYID \
  SECRET=MYAPISECRET \
  TEAMS="Employees,Contractors" \
  ADMIN_TEAMS="System Admins,Support" \
  sudo bash -E -
```

Be sure to either include the necessary environment variables as referenced in the command above, or expose them via the environment to ensure the agent is properly configured. The required variables are:

* `KEY` is the API key for your Github organization. This can be obtained through the [GitWarden dashboard](https://gitwarden.com) once your organization is added.

* `SECRET` is the API secret for the corresponding API key above. This is also obtainable through the [GitWarden dashboard](https://gitwarden.com).

* `TEAMS` is a comma-delimited string of Github team names, where the members of each team should have accounts created for them on the local system.

An optional variable is:

* `ADMIN_TEAMS` is a comma-delimited string of Github team names that should have administrative (`sudo`) access on the local system. Similar to `TEAMS` above, members of the `ADMIN_TEAMS` teams will have user accounts created for them on the local system with `sudo` access.

The `install.sh` script is the same script located under the `scripts/` directory, and is synced on a nightly basis. We recommend reviewing the script prior to running it.

#### Supported Distributions

The following Linux distributions are supported (with more on the way):

* Ubuntu - precise, trusty, wheezy, xenial, yakkety, zesty
* Debian - squeeze, jessie
* CentOS - 6, 7
* RedHat EL - 6, 7
* Amazon Linux - 2017.03, 2016.09, 2016.03, 2015.09, 2015.03

#### Package Repository

As an alternative to the scripted installation above, you can also configure your package manager to use the GitWarden package repository using the examples below.

##### yum/dnf

Write the contents below to the file `/etc/yum.repos.d/gitwarden.repo`:

```
[gitwarden]
name=GitWarden Package Repository
baseurl=https://archives.gitwarden.com/rpm
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://archives.gitwarden.com/gitwarden.key
```

Or copy and paste the command:

```sh
cat <<EOF | sudo tee /etc/yum.repos.d/gitwarden.repo
[gitwarden]
name=GitWarden Package Repository
baseurl=https://archives.gitwarden.com/rpm
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://archives.gitwarden.com/gitwarden.key
EOF
```

Once the repository is configured, install the agent with the command:

```sh
sudo yum install gitwarden-agent -y
```

##### apt

Run the commands below:

```sh
curl -sL https://archives.gitwarden.com/gitwarden.key | sudo apt-key add -
echo "deb https://archives.gitwarden.com/deb squeeze main" | sudo tee /etc/apt/sources.list.d/gitwarden.list
```

The `squeeze` in the second command above can be replaced with your current distribution codename (precise, jessie, etc), however they are interchangeable. Once the commands above have been run successfully, you can install the agent with the command:

```sh
sudo apt-get update && sudo apt-get install gitwarden-agent -y
```

### Configuring

If you used the script installation referenced above, then you do not need to perform any further configuration changes. If you installed the agent manually using the package repository, you will need to provide you API key and secret to the agent so that it can register properly the first time.

To set your API key, add the following entry to the configuration located at `/etc/gitwarden/gitwarden.yml`:

```yml
api_key: YOURAPIKEYHERE
```

In addition to the `api_key` setting, you will also want to set which teams should have access to the instance. This makes the final configuration look something like:

```yml
api_key: YOURAPIKEYHERE
teams:
  - People
admin_teams:
  - Admin People
```

And then register the agent with the command:

```sh
GITWARDEN_SECRET="YOURSECRETHERE" sudo gitwarden-agent register
```

Once registered, you will want to make sure the service is running:

```sh
# sysv systems (and some systemd systems)
sudo service gitwarden-agent restart

# systemd systems
sudo systemctl restart gitwarden-agent
```

### Troubleshooting

If any issues are encountered with the agent, it would be great if you could provide us with any logs or messages. On non-systemd systems, logs are located at `/var/log/gitwarden-agent.log`. On systemd systems, logs can be located with the command `sudo journalctl -u gitwarden-agent`. 

#### Debug Logging

If the error continues to occur but the logs aren't useful, you may need to enable debug logging. This can be done by setting the `log_level` configuration option to `DEBUG`. For example, adding this to your configuration:

```yml
log_level: DEBUG
```

### Issues?

For questions or problems, please either open a Github issue against this repository or send an email to support@gitwarden.com.
