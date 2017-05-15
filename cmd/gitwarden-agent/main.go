//
// Author: Ross McDonald (ross.mcdonald@gitwarden.com)
// Copyright 2017, Summonry Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

var (
	// version is the version of the running agent, which usually
	// corresponds to the git tag pointing at the commit the agent was built
	// from.
	version string
	// commit is the git commit used for building the agent.
	commit string
	// branch is the git branch used for building the agent.
	branch string
)

const (
	// defaultLogLevel is the log level used by the agent if not overriden
	// via the configuration. Valid values for defaultLogLevel are DEBUG,
	// INFO, WARN, ERROR.
	defaultLogLevel = "INFO"

	// defaultRefreshIntervalMin is the default refresh interval (in
	// minutes) for the agent if not overriden via the configuration.
	defaultRefreshIntervalMin = 5

	// defaultRegistryURL is the URL used by the agent for contacting the
	// GitWarden registry API.
	defaultRegistryURL = "https://gitwarden.com"
)

// config is the agent configuration
var config = viper.New()

// appData is the configuration read from the agent-controlled configuration.
var appData = viper.New()

// client is the HTTP client used by the application
var client = &http.Client{}

// Returns the SHA256 checksum of the specified key and data byte slices.
// Returns a byte slice representing the computed checksum.
func makeHmac(key []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}

// buildStringToSign collects the necessary portions of an HTTP request that are
// used for generating the GitWarden Authorization header (used for
// authenticating requests to the registry). Returns the aggregate string needed
// for signing.
func buildStringToSign(req *http.Request) string {
	body := []byte{}
	if req.Body != nil {
		reqBody, err := ioutil.ReadAll(req.Body)
		if err != nil {
			log.Warnf("Encountered error when reading request body: %s", err)
		}
		body = reqBody
		log.Debugf("Restoring body: %+v", reqBody)
		req.Body = ioutil.NopCloser(bytes.NewBuffer(reqBody))
		// req.Body = bytes.NewBuffer(reqBody)
	}
	s := strings.Join([]string{
		req.Method,
		req.URL.Path,
		string(body),
	}, "\n")
	log.Debugf("Built 'string to sign': %s", s)
	return s
}

// generateAuthSignature generates an Authorization header, which is included in
// requests to the GitWarden registry. The Authorization header represents
// knowledge of both the API key and secret/deployment ID, and is similar to the
// AWS authentication mechanism. If the agent is registering with the GitWarden
// service, the secret parameter should be the API key secret for the
// corresponding API key. Otherwise, the secret parameter should be the
// deployment ID. Returns the hash portion of the Authorization header.
func generateAuthSignature(req *http.Request, secret string) string {
	log.Debug("Generating request signature")
	s := buildStringToSign(req)
	signature := makeHmac([]byte(secret), []byte(s))
	return hex.EncodeToString(signature)
}

// TeamUser is a single user, representing a username and a list of SSH public
// keys
type TeamUser struct {
	Name string   `json:"name"`
	Keys []string `json:"keys"`
}

// Team is a logical collection of users, usually mapped to a unix group
type Team struct {
	Name  string     `json:"name"`
	Admin bool       `json:"admin"`
	Users []TeamUser `json:"users"`
}

// Deployment is an authentication context for applying to the system
type Deployment struct {
	Teams []Team `json:"teams"`
}

// register generates a new deployment (or auth configuration) with the
// GitWarden registry using the specified API key and teams. An error is
// returned if the deployment could not be created.
func register(apiKey, apiSecret string, teams, adminTeams []string) (*string, error) {
	log.Info("Registering with GitWarden service...")
	log.Debugf("Registering with teams %+v and adminTeams %+v", teams, adminTeams)

	url := strings.Join([]string{config.GetString("registry_url"), "d", apiKey}, "/")
	// FIXME(rossmcdonald) - The request payload should be generated in a
	// more reliable fashion (using the json encoding library instead of
	// string manipulation).
	payload := `{"teams":["` + strings.Join(teams, `","`) + `"],"teams_sudo":["` + strings.Join(adminTeams, `","`) + `"]}`
	b := bytes.NewBuffer([]byte(payload))
	// jsonStr := []byte(`{"title":"Buy cheese and bread for breakfast."}`)
	// log.Debugf("JSON payload: %+v", payload)
	req, err := http.NewRequest("POST", url, b)
	if err != nil {
		log.Errorf("Could not issue request to URL '%s': %s", url, err)
		return nil, err
	}
	authHeader := apiKey + ":" + generateAuthSignature(req, apiSecret)
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("Content-type", "application/json")
	req.Header.Set(
		"User-Agent",
		fmt.Sprintf(
			"GitWardenAgent/%s %s/%s",
			version,
			"?",
			config.GetString("hostname"),
		),
	)

	// req.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(payload)))
	// req.ContentLength = int64(len(payload))

	resp, err := client.Do(req)
	if err != nil {
		log.Errorf("Encountered error when registering with GitWarden registry: %s", err)
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Warnf("Encountered error when reading request body from POST request to %s: %s", url, err)
		return nil, err
	}
	if resp.StatusCode != 200 {
		err := fmt.Errorf("Retrieved non-200 response for request to GitWarden registry: %s", string(body))
		return nil, err
	}
	resp.Body.Close()

	deploymentID := string(body)

	log.Infof("Successfully registered as deployment ID %s", deploymentID)
	return &deploymentID, nil
}

// pullDeployment retrieves the specified deployment ID from the GitWarden
// database. The API key must also be supplied for signing of the request,
// authorizing retrieval of the deployment information. Returns a *Deployment to
// the deployment on success, and error otherwise.
func pullDeployment(apiKey, deploymentID string) (*Deployment, error) {
	log.Debugf("Retrieving deployment ID: %s", deploymentID)
	url := strings.Join([]string{config.GetString("registry_url"), "d", apiKey, deploymentID}, "/")
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Errorf("Could not issue request to URL '%s': %s", url, err)
	}
	authHeader := apiKey + ":" + generateAuthSignature(req, deploymentID)
	req.Header.Set("Authorization", authHeader)
	req.Header.Set(
		"User-Agent",
		fmt.Sprintf(
			"GitWardenAgent/%s %s/%s",
			version,
			deploymentID,
			config.GetString("hostname"),
		),
	)

	resp, err := client.Do(req)
	if err != nil {
		log.Errorf("Encountered error when pulling deployment %s: %s", deploymentID, err)
		return nil, err
	}
	if resp.StatusCode != 200 {
		var msg string
		if resp.StatusCode == 405 {
			msg = fmt.Sprintf("Has the deployment been deactivated? If so, you can re-activate the deployment by visiting the GitWarden dashboard at https://gitwarden.com/d/%s.", apiKey)
		} else if resp.StatusCode == 404 {
			msg = "Has the deployment been removed? If so, you may need to re-register with the registry. See https://gitwarden.com/documentation/faq#reregistering for more information."
		} else if resp.StatusCode == 401 {
			msg = "Note, this is usually caused by a signature mismatch."
		}

		err := fmt.Errorf("Retrieved non-200 response for request to deployment %s: %s ... %s", deploymentID, resp.Status, msg)
		return nil, err
	}
	// defer resp.Body.Close()

	dep := &Deployment{}
	err = json.NewDecoder(resp.Body).Decode(dep)
	if err != nil {
		log.Warnf("Encountered error decoding deployment response: %s", err)
		return nil, err
	}
	log.Debugf("Retrieved deployment: %+v", *dep)
	return dep, nil
}

// userExists checks to see if the specified username exists on the system.
// Returns true if the user exists, and false otherwise.
func userExists(u string) bool {
	log.Debug("Running lookup on user:", u)
	if _, err := user.Lookup(u); err != nil {
		if _, ok := err.(user.UnknownUserError); ok {
			log.Info("User does not exist: ", u)
			return false
		} else {
			log.Error("Encountered unknown error on user lookup: ", err)
			return false
		}
	}
	return true
}

// groupExists checks to see if the specified group name exists on the system.
// Returns true if the user exists, and false otherwise.
func groupExists(g string) bool {
	log.Debug("Running lookup on group:", g)
	if _, err := user.LookupGroup(g); err != nil {
		if _, ok := err.(user.UnknownGroupError); ok {
			log.Info("Group does not exist: ", g)
			return false
		} else {
			log.Error("Encountered unknown error on group lookup: ", err)
			return false
		}
	}
	return true
}

// userExistsInGroup checks to see if the specified username is present in the
// specified group. Returns true if the user exists, and false otherwise.
func userExistsInGroup(u, g string) bool {
	log.Debug("Checking that user %s is in group %s", u, g)
	luser, err := user.Lookup(u)
	if err != nil {
		return false
	}

	lgroups, err := luser.GroupIds()
	if err != nil {
		log.Errorf("Encountered error when retreiving groups for user %s: %s", luser.Name, err)
		return false
	}

	for _, gid := range lgroups {
		lgroup, err := user.LookupGroupId(gid)
		if err != nil {
			log.Infof("Encountered error when looking up group ID %s: %s	", gid, err)
			continue
		}

		if g == lgroup.Name {
			// Target group found, return
			log.Infof("User %s is in group %s", u, g)
			return true
		}
	}
	// Fall through signifies failure
	return false
}

// getGroupsForUser collects all of the groups that the specified user is in.
// Returns a list of *string (group names), or an error if the group listing
// could not be collected for any reason.
func getGroupsForUser(u string) ([]*string, error) {
	luser, err := user.Lookup(u)
	if err != nil {
		return nil, err
	}

	lgroups, err := luser.GroupIds()
	if err != nil {
		return nil, err
	}

	groupListing := []*string{}
	for _, lgroup := range lgroups {
		gr, err := user.LookupGroupId(lgroup)
		if err != nil {
			log.Warnf("Encountered error when looking up group ID %s: %s", lgroup, err)
			continue
		}
		groupListing = append(groupListing, &gr.Name)
	}
	return groupListing, nil
}

// getUsersInGroup collects all of the user.Users in the specified group.
// Returns a list of *user.User if successful, or an error is returned if the
// user listing could not be collected for any reason.
func getUsersInGroup(g string) ([]*user.User, error) {
	_, err := user.LookupGroup(g)
	if err != nil {
		log.Warnf("Encountered error when looking up group %s: %s", g, err)
		return nil, err
	}

	cmd := exec.Command("getent", "passwd")
	var out bytes.Buffer
	cmd.Stdout = &out
	err = cmd.Run()
	if err != nil {
		if strings.Contains(err.(*exec.Error).Error(), "executable file not found in $PATH") {
			log.Info("getent command unavailable")
			// FIXME - As a fallback, use /etc/passwd file
			return nil, err
		} else {
			log.Error("Encountered error when running command:", err)
			return nil, err
		}
	}

	userListing := []*user.User{}
	scanner := bufio.NewScanner(strings.NewReader(out.String()))
	for scanner.Scan() {
		l := strings.Split(scanner.Text(), ":")
		if len(l) > 0 {
			username := l[0]
			groups, err := getGroupsForUser(username)
			if err != nil {
				log.Warn("Encountered error when retrieving groups for user %s: %s", username, err)
				continue
			}
			for _, group := range groups {
				// Iterate over each group user is a part of
				if *group == g {
					// User is in target group, append to list
					u, err := user.Lookup(username)
					if err != nil {
						log.Warn("Encountered error on lookup for user %s: %s", username, err)
						break
					}
					userListing = append(userListing, u)
				}
			}
		}
	}
	return userListing, nil
}

// getGroupUserMapping captures the current user-group state of the system.
// Returns a map with keys being group names (string), and values as list of
// *user.User. An error is returned if the mapping could not be retrieved for
// any reason.
func getGroupUserMapping() (map[string][]*user.User, error) {
	cmd := exec.Command("getent", "group")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		if strings.Contains(err.(*exec.Error).Error(), "executable file not found in $PATH") {
			log.Info("getent command unavailable")
			// FIXME(rossmcdonald) - As a fallback, use /etc/passwd
			// file
			return nil, err
		} else {
			log.Error("Encountered error when running command:", err)
			return nil, err
		}
	}

	mapping := map[string][]*user.User{}
	scanner := bufio.NewScanner(strings.NewReader(out.String()))
	for scanner.Scan() {
		l := strings.Split(scanner.Text(), ":")
		if len(l) > 0 {
			groupname := l[0]
			userlisting, err := getUsersInGroup(groupname)
			if err != nil {
				log.Warn("Encountered error when retrieving users for group %s: %s", groupname, err)
				continue
			}
			mapping[groupname] = userlisting
		}
	}
	return mapping, nil
}

// createUser creates a user on the system with the specified user name. The
// default parameters for user creation are used (see `man useradd` for more
// detailed information), and no other customization is done. Returns an error
// if the user could not be created.
func createUser(username string) error {
	log.Info("Creating user: ", username)
	command := "useradd"
	params := []string{username}

	err := exec.Command(command, params...).Run()
	if err != nil {
		log.Errorf("Encountered error when running command '%s': %s", strings.Join(append([]string{command}, params...), " "), err)
		return err
	}

	return nil
}

// createGroup creates a group with the specified name. An error is returned if
// the group could not be created.
func createGroup(groupname string) error {
	log.Debug("Creating group: ", groupname)
	command := "groupadd"
	params := []string{groupname}

	err := exec.Command(command, params...).Run()
	if err != nil {
		log.Errorf("Encountered error when running command '%s': %s", strings.Join(append([]string{command}, params...), " "), err)
		return err
	}

	return nil
}

// deleteUser deletes the specified user from the system. In addition to removal
// from the system user registry, their home directory is also erased. An error
// is returned if the user could not be removed for any reason.
func deleteUser(username string) error {
	log.Infof("Deleting user: %s", username)
	command := "userdel"
	// FIXME - Remove (-r) should be an optional thing, and not assumed
	params := []string{"-r", username}

	err := exec.Command(command, params...).Run()
	if err != nil {
		log.Errorf("Encountered error when running command '%s': %s", strings.Join(append([]string{command}, params...), " "), err)
		return err
	}

	return nil
}

// addUserToGroup adds the specified user to the specified group as a secondary
// Unix group. An error is returned if the user could not be added to the target
// group for any reason.
func addUserToGroup(u, g string) error {
	log.Infof("Adding user '%s' to group '%s'", u, g)
	command := "usermod"
	params := []string{"-a", "-G", g, u}

	err := exec.Command(command, params...).Run()
	if err != nil {
		log.Errorf("Encountered error when running command '%s': %s", strings.Join(append([]string{command}, params...), " "), err)
		return err
	}

	return nil
}

// removeUserFromGroup removes a specified user from the specified group. An
// error is returned if the user could not be removed from the group.
func removeUserFromGroup(u, g string) error {
	log.Infof("Removing user '%s' from group '%s'", u, g)
	command := "deluser"
	params := []string{u, g}

	err := exec.Command(command, params...).Run()
	if err != nil {
		log.Errorf("Encountered error when running command '%s': %s", strings.Join(append([]string{command}, params...), " "), err)
		return err
	}

	return nil
}

// setAuthKeysForUser persists the provided SSH public keys to the provided
// user's `~/.ssh/authorized-keys` file, allowing them to use the corresponding
// private keys to login. It returns an error if the keys could not be persisted
// for any reason.
func setAuthKeysForUser(u string, keys []string) error {
	log.Debugf("Adding %d keys to user %s's authorized-key listing", len(keys), u)
	luser, err := user.Lookup(u)
	if err != nil {
		return err
	}
	if luser.HomeDir != "" {
		// Create ~/.ssh directory for user
		command := "mkdir"
		params := []string{"-p", luser.HomeDir + "/.ssh"}
		err = exec.Command(command, params...).Run()
		if err != nil {
			log.Warnf("Encountered error: %s", err)
		}

		// FIXME(rossmcdonald) - Don't overwrite key file on every run.
		// Instead, existing authorized-keys should be parsed to add any
		// keys not already present (allowing users to add extra keys
		// without them getting overwritten).

		// Write public keys to authorized-keys file
		data := []byte(strings.Join(keys, "\n") + "\n")
		err = ioutil.WriteFile(luser.HomeDir+"/.ssh/"+"authorized-keys", data, 0644)
		if err != nil {
			log.Warnf("Encountered error when writing SSH keys for user '%s': %s", u, err)
			return err
		}
	} else {
		return fmt.Errorf("Could not find home directory for user %s, unable to persist SSH keys", u)
	}
	return nil
}

// chownHomeDir executes a `chown` command on the home directory of the specifed
// username, setting recursive permissions on the home directory so that the
// owner is the user (group is the user's primary group, usually their
// username). This should only be run after user creation to ensure no
// permissions are unintentionally modified for an existing user. Returns an
// error if permissions could not be set.
func chownHomeDir(u string) error {
	log.Debugf("Setting permissions on home directory for user: %s", u)
	luser, err := user.Lookup(u)
	if err != nil {
		return err
	}
	if luser.HomeDir != "" {
		command := "chown"
		params := []string{"-R", luser.Username + ":" + luser.Gid, luser.HomeDir}
		cmd := exec.Command(command, params...)
		var out bytes.Buffer
		cmd.Stderr = &out
		err = cmd.Run()
		if err != nil {
			log.Warnf("Encountered error when running command '%s': %s (%s)", strings.Join(append([]string{command}, params...), " "), err, out)
			return err
		}
	} else {
		return fmt.Errorf("Could not find home directory for user %s, unable to set permissions", u)
	}
	return nil
}

// applyDeployment applies the specified Deployment to the local system,
// creating/removing users and configuring SSH key authentication. Returns an
// error if an error occurred while the Deployment configuration was being
// applied.
func applyDeployment(dep *Deployment) error {
	log.Debug("Applying auth configuration to the local system")

	// Create a wait group that will be used to ensure all goroutines are
	// completed
	var wg sync.WaitGroup

	// Collect the current user-group mapping for the local system
	currentMapping, err := getGroupUserMapping()
	if err != nil {
		log.Errorf("Could not retrieve current user-group mapping for the local system: %s", err)
		return err
	}

	// Create a set (implemented as a map) representing all users currently
	// on the system
	existingUsers := map[string]bool{}
	for _, users := range currentMapping {
		// For each group
		for _, u := range users {
			// For each user in group
			if _, ok := existingUsers[u.Username]; !ok {
				// User exists, mark as true
				existingUsers[u.Username] = true
			}
		}
	}

	// Create a 'gitwarden-managed' group, which will contain all
	// GitWarden-tracked users in it.
	if _, ok := currentMapping["gitwarden-managed"]; !ok {
		// Group doesnt exist, create it
		if err := createGroup("gitwarden-managed"); err != nil {
			log.Warnf("Encountered error when creating group %s: %s ... continuing.", "gitwarden-managed", err)
		}
	}

	// Track new users being added to the system
	mNewUsers := map[string]bool{}
	// Track new teams being added
	mNewTeams := map[string]bool{}

	for _, team := range dep.Teams {
		// Mark this team as included in the latest deployment
		mNewTeams[team.Name] = true

		// Check to see if group exists for team
		if _, ok := currentMapping[team.Name]; !ok {
			// Group doesnt exist, create it
			if err := createGroup(team.Name); err != nil {
				log.Warnf("Encountered error when creating group %s: %s ... continuing.", team.Name, err)
			}
		}

		// Ensure group has correct admin privileges
		sudoersPath := "/etc/sudoers.d/gitwarden-" + team.Name
		if team.Admin {
			if _, err := os.Stat(sudoersPath); err != nil {
				if os.IsNotExist(err) {
					log.Infof("Updating group '%s' to have administrative access", team.Name)

					// FIXME(rossmcdonald) - Add option for
					// password-less sudo access.

					data := []byte(fmt.Sprintf("%%%s ALL=(ALL:ALL) ALL\n", team.Name))
					log.Debugf("Writing sudoers file %s for group %s with contents: %s", sudoersPath, team.Name, strings.Trim(string(data), "\n"))
					err = ioutil.WriteFile(sudoersPath, data, 0440)
					if err != nil {
						log.Warnf("Unable to set admin permissions for group %s: %s", team.Name, err)
					}
				} else {
					log.Warnf("Unable to stat sudoers file %s: %s", sudoersPath, err)
					return err
				}
			} else {
				// FIXME(rossmcdonald) - Check sudoers file for
				// correctness
			}
		} else {
			if _, err := os.Stat(sudoersPath); err == nil {
				log.Infof("Found pre-existing admin configuration for (now) non-admin team %s, removing...", team.Name)
				os.Remove(sudoersPath)
			}
		}

		// Add users specified in the auth configuration
		for _, u := range team.Users {
			_, ok := existingUsers[u.Name]
			if !ok && !mNewUsers[u.Name] {
				// User does not exist or we have already done a
				// pass on them
				if err := createUser(u.Name); err != nil {
					log.Warnf("Encountered error when creating user %s: %s ... continuing.", u.Name, err)
				}
				wg.Add(1)
				go func() {
					defer wg.Done()

					// Calling 'chown' too early will return
					// an error, since the home directory
					// might not exist yet. Adding a sleep
					// to ensure we wait long enough for the
					// home directory to be created.

					// FIXME(rossmcdonald) - Instead of
					// sleep, we should wait for the
					// directory to be created.
					time.Sleep(500 * time.Millisecond)

					// Set correct permissions on user's
					// home directory
					if err := chownHomeDir(u.Name); err != nil {
						log.Warnf("Encountered error when setting permissions on %s's home directory: %s ... continuing.", u.Name, err)
					}
				}()

				err := addUserToGroup(u.Name, "gitwarden-managed")
				if err != nil {
					log.Warnf("Encountered error when adding user '%s' to group '%s': %s", u.Name, "gitwarden-managed", err)
				}
			}

			if !mNewUsers[u.Name] {
				// Persist SSH keys
				err = setAuthKeysForUser(u.Name, u.Keys)
				if err != nil {
					log.Warnf("Encountered error when persisting keys for user '%s': %s ... continuing.", u.Name, err)
				}
			}

			// Mark this user as new
			mNewUsers[u.Name] = true

			// Check to see if user is already in group
			userInGroup := false
			for _, user := range currentMapping[team.Name] {
				if user.Username == u.Name {
					// User is already in group
					userInGroup = true
				}
			}
			if !userInGroup {
				// Add user to appropriate group
				err := addUserToGroup(u.Name, team.Name)
				if err != nil {
					log.Warnf("Encountered error when adding user '%s' to group '%s': %s", u.Name, team.Name, err)
				}
			}
		}

		// Look for (and remove) any extra users from the group
		for _, user := range currentMapping[team.Name] {
			if _, ok := mNewUsers[user.Username]; !ok {
				// User is not present in latest configuration,
				// remove them from the group.
				if err := removeUserFromGroup(user.Username, team.Name); err != nil {
					log.Warnf("Encountered error when removing user '%s' from group '%s': %s", user.Username, team.Name, err)
				}
			}
		}
	}

	// Compare users currently in the gitwarden-managed group, and remove
	// any users not listed in this deployment
	gwManagedUsers, err := getUsersInGroup("gitwarden-managed")
	if err != nil {
		log.Warn("Encountered error when retrieving users for the 'gitwarden-managed' group: %s", err)
	} else {
		for _, user := range gwManagedUsers {
			if _, ok := mNewUsers[user.Username]; !ok {
				// If user is not present in the latest
				// deployment, remove them
				log.Infof("User '%s' is no longer present in any configured teams, removing...", user.Username)
				deleteUser(user.Username)
			}
		}
	}

	// FIXME(rossmcdonald) - Look at teams under gitwarden-managed, and
	// remove teams that are no longer listed in the deployment (requires
	// that we track which teams were created by the agent in a reliable
	// way).

	wg.Wait()
	return nil
}

func registerAgent() {
	apiKey := config.GetString("api_key")
	apiSecret := config.GetString("api_secret")

	if apiKey == "" {
		// Error out if apiKey is not specified
		log.Fatal("An API key must be specified to continue. Please visit https://gitwarden.com for more information.")
	}

	if apiSecret == "" {
		// Error out if apiSecret is not specified
		log.Fatal("An API secret must be provided in order to register. Please visit https://gitwarden.com for more information.")
	}

	teams := config.GetStringSlice("teams")
	admin_teams := config.GetStringSlice("admin_teams")
	if len(teams) <= 0 {
		log.Fatalf("A 'teams' list must be specified in order to continue. Please see https://gitwarden.com/documentation/getting-started for more information.")
	}
	deploymentID, err := register(apiKey, apiSecret, teams, admin_teams)
	if err != nil {
		log.Fatalf("Encountered error when registering with GitWarden registry: %s", err)
	}
	appData.Set("deployment_id", deploymentID)

	log.Debugf("Persisting application data to: %s", appData.ConfigFileUsed())
	data, err := yaml.Marshal(appData.AllSettings())
	if err != nil {
		log.Errorf("Could not retrieve agent data: %s", err)
	}
	err = ioutil.WriteFile(appData.ConfigFileUsed(), data, 0640)
	if err != nil {
		log.Errorf("Could not persist agent data to %s: %s", appData.ConfigFileUsed(), err)
	}
}

func initConfig() {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
		DisableColors: true,
	})

	config.SetEnvPrefix("gitwarden") // Look for env variables that start with GITWARDEN_
	config.SetConfigName("gitwarden")
	config.AddConfigPath("/etc/gitwarden/")
	config.AddConfigPath("/etc/gitwarden/")
	config.AddConfigPath("$HOME/.gitwarden")
	config.AddConfigPath(".")

	appData.SetEnvPrefix("gitwarden") // Look for env variables that start with GITWARDEN_
	appData.SetConfigName("gitwarden-data")
	appData.AddConfigPath("/var/lib/gitwarden/")
	appData.AddConfigPath("$HOME/.gitwarden")
	appData.AddConfigPath(".")

	config.SetDefault("refresh_interval", defaultRefreshIntervalMin)
	config.SetDefault("log_level", defaultLogLevel)
	config.SetDefault("registry_url", defaultRegistryURL)

	hostname, err := os.Hostname()
	if err != nil {
		log.Warnf("Unable to retrieve system hostname, using name 'host' instead")
		hostname = "host"
	}
	config.SetDefault("hostname", hostname)

	appData.SetConfigType("yaml")
	if err := appData.ReadInConfig(); err != nil {
		log.Warnf("Could not read data file: %s", err)
	}

	config.SetConfigType("yaml")
	if err := config.ReadInConfig(); err != nil {
		log.Warnf("Could not read config file: %s", err)
	}

	log.Infof("GitWarden Agent v%s (commit %s, branch %s)", version, commit, branch)
	log.Infof("Using data file: %s", appData.ConfigFileUsed())
	log.Infof("Using configuration file: %s", config.ConfigFileUsed())
	appData.AutomaticEnv()
	config.AutomaticEnv()

	switch logLevel := config.Get("log_level"); logLevel {
	case "DEBUG":
		log.SetLevel(log.DebugLevel)
	case "INFO":
		log.SetLevel(log.InfoLevel)
	case "WARN":
		log.SetLevel(log.WarnLevel)
	case "ERROR":
		log.SetLevel(log.ErrorLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}
}

func init() {
	if version == "" {
		version = "?"
	}
	if commit == "" {
		commit = "?"
	}
	if branch == "" {
		branch = "?"
	}
}

func main() {
	var cmdRun = &cobra.Command{
		Use:   "run",
		Short: "Run agent",
		Run: func(cmd *cobra.Command, args []string) {
			initConfig()

			deploymentID := appData.GetString("deployment_id")
			if deploymentID == "" {
				// No deployment ID provided or found, start the registration process
				registerAgent()
			}

			apiKey := config.GetString("api_key")
			if apiKey == "" {
				// Error out if apiKey is not specified
				log.Fatal("An API key must be specified to continue. Please visit https://gitwarden.com for more information.")
			}

			for {
				// Main loop
				d, err := pullDeployment(apiKey, appData.GetString("deployment_id"))
				if err != nil {
					log.Errorf("Encountered error when retrieving deployment: %s", err)

					// FIXME(rossmcdonald) - Provide option for
					// self-destructing (remove all users, groups, and wipe
					// configuration) after a certain number of failures.
				} else {
					err = applyDeployment(d)
					if err != nil {
						log.Errorf("Encountered error when applying deployment configuration: ", err)
					}
				}
				log.Debug("Sleeping... zzz")
				time.Sleep(time.Duration(config.GetInt("refresh_interval")) * time.Minute)
			}
		},
	}
	var cmdRegister = &cobra.Command{
		Use:   "register",
		Short: "Register with the GitWarden service",
		Long:  `register is used to register the local instance with the GitWarden Registry. This command requires an API secret being exposed through the environment. For example: SECRET=MYAPISECRET gitwarden register`,
		Run: func(cmd *cobra.Command, args []string) {
			initConfig()
			registerAgent()
		},
	}
	var cmdVersion = &cobra.Command{
		Use:   "version",
		Short: "Display version of the gitwarden-agent",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("v%s (commit %s, branch %s)\n", version, commit, branch)
		},
	}
	var rootCmd = &cobra.Command{Use: "gitwarden-agent"}
	rootCmd.AddCommand(cmdRegister)
	rootCmd.AddCommand(cmdRun)
	rootCmd.AddCommand(cmdVersion)
	rootCmd.Execute()
}
