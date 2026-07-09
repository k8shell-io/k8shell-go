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
func (c *Client) GetProfile(ctx context.Context) (*models.User, error) {
	var u models.User
	if err := c.get(ctx, "/api/v1/me/profile", &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// ListUsers returns all users visible to the authenticated token.
func (c *Client) ListUsers(ctx context.Context) ([]models.User, error) {
	var users []models.User
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
func (c *Client) GetUserProfile(ctx context.Context, username string) (*models.User, error) {
	var u models.User
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

// SetUserPassword sets or replaces the named user's local password and returns
// the updated record. Pass an empty username to set the authenticated user's own
// password. The server bcrypt-hashes the password before persisting it.
func (c *Client) SetUserPassword(ctx context.Context, username, password string) (*models.User, error) {
	var u models.User
	if err := c.put(ctx, c.userPath(username)+"/password", models.UserPasswordRequest{Password: &password}, &u); err != nil {
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

// GetUserCredential returns the named user's credential for the given external service.
func (c *Client) GetUserCredential(ctx context.Context, username, serviceName string) (*models.UserCredential, error) {
	var cred models.UserCredential
	if err := c.get(ctx, c.userPath(username)+"/credentials/"+serviceName, &cred); err != nil {
		return nil, err
	}
	return &cred, nil
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
