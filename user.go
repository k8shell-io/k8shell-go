// Copyright 2026 The k8shell Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package k8shell

import "github.com/k8shell-io/common/pkg/models"

// GetProfile returns the profile of the authenticated user.
func (c *Client) GetProfile() (*models.User, error) {
	var u models.User
	if err := c.get("/api/v1/me/profile", &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// ListUsers returns all users visible to the authenticated token.
func (c *Client) ListUsers() ([]models.User, error) {
	var users []models.User
	if err := c.get("/api/v1/users", &users); err != nil {
		return nil, err
	}
	return users, nil
}

// ListSessions returns SSH sessions for the given username, or for the
// authenticated user when username is empty. When all is true, all sessions
// (including ended ones) are returned.
func (c *Client) ListSessions(username string, all bool) ([]models.SSHSession, error) {
	path := c.userPath(username) + "/sessions"
	if all {
		path += "?all=true"
	}
	var sessions []models.SSHSession
	if err := c.get(path, &sessions); err != nil {
		return nil, err
	}
	return sessions, nil
}
