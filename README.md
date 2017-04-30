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

### Issues?

For questions or problems, please either open a Github issue against this repository or send an email to support@gitwarden.com.
