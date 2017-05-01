# gitwarden-agent

The `gitwarden-agent` is a Linux user management daemon, used for communicating with the GitWarden registry and syncing Github team changes to the local system. 

You can find more information regarding the GitWarden service [here](https://gitwarden.com).

### Installation

The easiest method for installing the agent is to run the following command from any instance that you need bootstrapped:

```sh
curl -sL https://archives.gitwarden.com/install.sh | \
  KEY=afghanistan \
  SECRET=bananistan \
  TEAMS=("Employees") \
  ADMIN_TEAMS=("System Admins" "Support") \
  sudo bash -
```

Be sure to either include the necessary environment variables as referenced in the command above, or expose them via the environment to ensure the agent is properly configured. The required variables are:

* `KEY` is the API key for your Github organization. This can be obtained through the [GitWarden dashboard](https://gitwarden.com) once your organization is added.

* `SECRET` is the API secret for the corresponding API key above. This is also obtainable through the [GitWarden dashboard](https://gitwarden.com).

* `TEAMS` is an array of Github team names, where the members of each team should have accounts created for them on the local system.

An optional variable is:

* `ADMIN_TEAMS` is an array of Github team names that should have administrative (`sudo`) access on the local system. Similar to `TEAMS` above, members of the `ADMIN_TEAMS` teams will have user accounts created for them on the local system with `sudo` access.

The `install.sh` script is the same script located under the `scripts/` directory, and is synced on a nightly basis. We recommend reviewing the script prior to running it.

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
gpgkey=https://archives.gitwarden.com/gitwarden.key
```

Or copy and paste the command:

```
cat <<EOF | sudo tee /etc/yum.repos.d/gitwarden.repo
[gitwarden]
name=GitWarden Package Repository
baseurl=https://archives.gitwarden.com/rpm
enabled=1
gpgcheck=1
gpgkey=https://archives.gitwarden.com/gitwarden.key
EOF
```

Once the repository is configured, install the agent with the command:

```
yum install gitwarden-agent
```

##### apt

Run the commands below:

```
curl -sL https://archives.gitwarden.com/gitwarden.key | sudo apt-key add -
echo "deb https://archives.gitwarden.com/deb squeeze main" | sudo tee /etc/apt/sources.list.d/gitwarden.list
```

The `squeeze` in the second command above can be replaced with your current distribution codename (precise, jessie, etc), however they are interchangeable. Once the commands above have been run successfully, you can install the agent with the command:

```
apt-get update && apt-get install gitwarden-agent -y
```

### Configuring

If you used the script installation referenced above, then you do not need to perform any further configuration changes. If you installed the agent manually using the package repository, you will need to provide you API key and secret to the agent so that it can register properly the first time.

To set your API key, add the following entry to the configuration located at `/etc/gitwarden/gitwarden.yml`:

```
api_key: YOURAPIKEYHERE
```

In addition to the `api_key` setting, you will also want to set which teams should have access to the instance. This makes the final configuration look something like:

```
api_key: YOURAPIKEYHERE
teams:
  - People
admin_teams:
  - Admin People
```

And then register the agent with the command:

```
GITWARDEN_SECRET="YOURSECRETHERE" sudo gitwarden-agent --register
```

Once registered, you will want to make sure the service is running:

```
service gitwarden-agent restart
```

### Issues?

For questions or problems, please either open a Github issue against this repository or send an email to support@gitwarden.com.
