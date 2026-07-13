// Copyright 2026 The k8shell Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package k8shell

import (
	"context"
	"net/url"
	"strconv"

	"github.com/k8shell-io/common/pkg/models"
)

// GetProfile returns the profile of the authenticated user.
func (c *Client) GetProfile(ctx context.Context) (*models.UserProfile, error) {
	var u models.UserProfile
	if err := c.get(ctx, "/api/v1/me/profile", &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// GetCapabilities returns the named user's policy capabilities: which actions
// they are allowed or denied, why, and any obligations attached. Pass an empty
// username for the authenticated user's own capabilities. resourceOwner, if
// non-empty, checks capabilities as they'd apply to resources owned by that
// user (e.g. an org-scoped policy obligation) rather than the caller's own.
func (c *Client) GetCapabilities(ctx context.Context, username, resourceOwner string) ([]models.Capability, error) {
	path := c.userPath(username) + "/capabilities"
	if resourceOwner != "" {
		q := url.Values{}
		q.Set("resource_owner", resourceOwner)
		path += "?" + q.Encode()
	}
	var caps []models.Capability
	if err := c.get(ctx, path, &caps); err != nil {
		return nil, err
	}
	return caps, nil
}

// ListUsers returns the profiles of all users visible to the authenticated token.
func (c *Client) ListUsers(ctx context.Context) ([]models.UserProfile, error) {
	var users []models.UserProfile
	if err := c.get(ctx, "/api/v1/users", &users); err != nil {
		return nil, err
	}
	return users, nil
}

// CreateUser creates a new local user record with no backing identity provider
// and returns it. Only admin tokens can create users.
func (c *Client) CreateUser(ctx context.Context, req models.UserCreateRequest) (*models.User, error) {
	var u models.User
	if err := c.post(ctx, "/api/v1/users", req, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// DeleteUser permanently deletes the named user. Only admin tokens can delete users.
func (c *Client) DeleteUser(ctx context.Context, username string) error {
	return c.delete(ctx, c.userPath(username))
}

// GetUserProfile returns the profile of the named user.
func (c *Client) GetUserProfile(ctx context.Context, username string) (*models.UserProfile, error) {
	var u models.UserProfile
	if err := c.get(ctx, c.userPath(username)+"/profile", &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// UpdateUserProfile applies a partial update to the named user's profile and returns
// the updated record. Only admin tokens can update other users; a token updating
// itself may be limited to a subset of fields by the server.
func (c *Client) UpdateUserProfile(ctx context.Context, username string, req models.UserUpdateRequest) (*models.User, error) {
	var u models.User
	if err := c.patch(ctx, c.userPath(username)+"/profile", req, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// ClearUserPasswordLockout clears the named user's transient brute-force
// lockout on password auth (UserProfile.PasswordLocked), leaving any
// admin-set account lock (UserProfile.AccountLocked) untouched.
func (c *Client) ClearUserPasswordLockout(ctx context.Context, username string) error {
	return c.delete(ctx, c.userPath(username)+"/password-lockout")
}

// SetUserPassword sets or replaces the named user's local password and returns
// the updated record. Pass an empty username to set the authenticated user's own
// password. currentPassword is required by the server when a non-sudo user is
// changing their own password, and ignored otherwise; pass "" when not needed.
// The server bcrypt-hashes the password before persisting it.
func (c *Client) SetUserPassword(ctx context.Context, username, password, currentPassword string) (*models.User, error) {
	req := models.UserPasswordRequest{Password: &password}
	if currentPassword != "" {
		req.CurrentPassword = &currentPassword
	}
	var u models.User
	if err := c.put(ctx, c.userPath(username)+"/password", req, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// GetUserBlueprints returns the blueprint names the named user is allowed to use.
func (c *Client) GetUserBlueprints(ctx context.Context, username string) ([]string, error) {
	var blueprints []string
	if err := c.get(ctx, c.userPath(username)+"/blueprints", &blueprints); err != nil {
		return nil, err
	}
	return blueprints, nil
}

// AddUserRoles grants the given roles to the named user, in addition to any existing roles.
func (c *Client) AddUserRoles(ctx context.Context, username string, roles []models.Role) error {
	return c.post(ctx, c.userPath(username)+"/roles", models.UserRolesRequest{Roles: roles}, nil)
}

// RemoveUserRoles revokes the given roles from the named user, leaving other roles untouched.
func (c *Client) RemoveUserRoles(ctx context.Context, username string, roles []models.Role) error {
	return c.deleteWithBody(ctx, c.userPath(username)+"/roles", models.UserRolesRequest{Roles: roles})
}

// AddUserBlueprints grants the given blueprints to the named user, in addition to any existing ones.
func (c *Client) AddUserBlueprints(ctx context.Context, username string, blueprints []string) error {
	return c.post(ctx, c.userPath(username)+"/blueprints", models.UserBlueprintsRequest{Blueprints: blueprints}, nil)
}

// RemoveUserBlueprints revokes the given blueprints from the named user, leaving others untouched.
func (c *Client) RemoveUserBlueprints(ctx context.Context, username string, blueprints []string) error {
	return c.deleteWithBody(ctx, c.userPath(username)+"/blueprints", models.UserBlueprintsRequest{Blueprints: blueprints})
}

// AddUserKeys adds the given SSH public keys to the named user, in addition to any existing keys.
func (c *Client) AddUserKeys(ctx context.Context, username string, keys []string) error {
	return c.post(ctx, c.userPath(username)+"/keys", models.UserKeysRequest{Keys: keys}, nil)
}

// ListUserAuthKeys returns the SSH public keys registered for the named user, in
// digest (fingerprint) form. Each key's Index identifies its position for use
// with RemoveUserAuthKey.
func (c *Client) ListUserAuthKeys(ctx context.Context, username string) ([]models.UserAuthKey, error) {
	q := url.Values{}
	q.Set("format", "digest")
	var keys []models.UserAuthKey
	if err := c.get(ctx, c.userPath(username)+"/keys?"+q.Encode(), &keys); err != nil {
		return nil, err
	}
	return keys, nil
}

// RemoveUserAuthKey removes a single SSH public key from the named user, identified
// by its index in the list returned by ListUserAuthKeys. The authenticated token
// identifies who is performing the removal; username identifies whose key it is.
func (c *Client) RemoveUserAuthKey(ctx context.Context, username string, index int) error {
	return c.delete(ctx, c.userPath(username)+"/keys/"+strconv.Itoa(index))
}

// ListUserCredentials returns the external service credentials stored for the named user.
func (c *Client) ListUserCredentials(ctx context.Context, username string) ([]models.UserCredential, error) {
	var creds []models.UserCredential
	if err := c.get(ctx, c.userPath(username)+"/credentials", &creds); err != nil {
		return nil, err
	}
	return creds, nil
}

// GetUserCredential returns the named user's credential with the given ID.
func (c *Client) GetUserCredential(ctx context.Context, username string, id uint32) (*models.UserCredential, error) {
	q := url.Values{}
	q.Set("id", strconv.FormatUint(uint64(id), 10))
	var creds []models.UserCredential
	if err := c.get(ctx, c.userPath(username)+"/credentials?"+q.Encode(), &creds); err != nil {
		return nil, err
	}
	if len(creds) == 0 {
		return nil, &APIError{StatusCode: 404, Message: "credential not found"}
	}
	return &creds[0], nil
}

// UpdateUserCredential partially updates the named user's credential with the given
// ID and returns the updated record. Only non-nil fields in req are applied.
func (c *Client) UpdateUserCredential(ctx context.Context, username string, id uint32, req models.UserCredentialUpdateRequest) (*models.UserCredential, error) {
	q := url.Values{}
	q.Set("id", strconv.FormatUint(uint64(id), 10))
	var out models.UserCredential
	if err := c.patch(ctx, c.userPath(username)+"/credentials?"+q.Encode(), req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteUserCredential deletes the named user's credential with the given ID.
func (c *Client) DeleteUserCredential(ctx context.Context, username string, id uint32) error {
	q := url.Values{}
	q.Set("id", strconv.FormatUint(uint64(id), 10))
	return c.delete(ctx, c.userPath(username)+"/credentials?"+q.Encode())
}

// AddKubernetesUserCredential provisions a Kubernetes service-account credential for
// the named user and returns the stored record.
func (c *Client) AddKubernetesUserCredential(ctx context.Context, username string, req models.UserKubernetesCredentialRequest) (*models.UserCredential, error) {
	var out models.UserCredential
	if err := c.post(ctx, c.userPath(username)+"/credentials/kubernetes", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AddGitUserCredential stores a Git credential for the named user and returns the
// stored record.
func (c *Client) AddGitUserCredential(ctx context.Context, username string, req models.UserGitCredentialRequest) (*models.UserCredential, error) {
	var out models.UserCredential
	if err := c.post(ctx, c.userPath(username)+"/credentials/git", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AddRegistryUserCredential stores a container registry credential for the named user
// and returns the stored record.
func (c *Client) AddRegistryUserCredential(ctx context.Context, username string, req models.UserRegistryCredentialRequest) (*models.UserCredential, error) {
	var out models.UserCredential
	if err := c.post(ctx, c.userPath(username)+"/credentials/registry", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListUserTokens returns the personal access tokens issued for the named user.
// The raw token values are never returned, only metadata (name, scopes, preview, etc).
func (c *Client) ListUserTokens(ctx context.Context, username string) ([]models.AccessToken, error) {
	var tokens []models.AccessToken
	if err := c.get(ctx, c.userPath(username)+"/tokens", &tokens); err != nil {
		return nil, err
	}
	return tokens, nil
}

// GetUserToken returns the named user's personal access token with the given ID.
// The server has no single-token lookup endpoint, so this filters the result of
// ListUserTokens client-side.
func (c *Client) GetUserToken(ctx context.Context, username string, id int64) (*models.AccessToken, error) {
	tokens, err := c.ListUserTokens(ctx, username)
	if err != nil {
		return nil, err
	}
	for _, t := range tokens {
		if t.ID == id {
			return &t, nil
		}
	}
	return nil, &APIError{StatusCode: 404, Message: "token not found"}
}

// CreateUserToken issues a new personal access token for the named user and
// returns its ID and raw secret value. The secret is returned exactly once —
// it cannot be retrieved again after this call.
func (c *Client) CreateUserToken(ctx context.Context, username string, req models.AccessTokenCreateRequest) (*models.AccessTokenCreated, error) {
	var out models.AccessTokenCreated
	if err := c.post(ctx, c.userPath(username)+"/tokens", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateUserToken partially updates the named user's personal access token with
// the given ID — its active state and/or scopes — and returns the updated
// record. Name and expiry are immutable after creation.
func (c *Client) UpdateUserToken(ctx context.Context, username string, id int64, req models.AccessTokenUpdateRequest) (*models.AccessToken, error) {
	var out models.AccessToken
	if err := c.patch(ctx, c.userPath(username)+"/tokens/"+strconv.FormatInt(id, 10), req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteUserToken revokes the named user's personal access token with the given ID.
func (c *Client) DeleteUserToken(ctx context.Context, username string, id int64) error {
	return c.delete(ctx, c.userPath(username)+"/tokens/"+strconv.FormatInt(id, 10))
}

// ListSessions returns SSH sessions visible to the authenticated token.
// When username or workspace is non-empty, results are filtered accordingly.
// When limit is greater than zero, results are capped to the last limit sessions.
// When all is true, all sessions (including ended ones) are returned.
func (c *Client) ListSessions(ctx context.Context, username, workspace string, limit int, all bool) ([]models.SSHSession, error) {
	q := url.Values{}
	if username != "" {
		q.Set("username", username)
	}
	if workspace != "" {
		q.Set("workspace", workspace)
	}
	if limit > 0 {
		q.Set("last_n", strconv.Itoa(limit))
	}
	if all {
		q.Set("all", "true")
	}
	path := "/api/v1/sessions"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var sessions []models.SSHSession
	if err := c.get(ctx, path, &sessions); err != nil {
		return nil, err
	}
	return sessions, nil
}
