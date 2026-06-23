// Copyright 2026 The k8shell Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package k8shell

import (
	"context"
	"net/url"

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

// ListSessions returns SSH sessions for the given username, or for the
// authenticated user when username is empty. When all is true, all sessions
// (including ended ones) are returned.
func (c *Client) ListSessions(ctx context.Context, username string, all bool) ([]models.SSHSession, error) {
	q := url.Values{}
	if all {
		q.Set("all", "true")
	}
	path := c.userPath(username) + "/sessions"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var sessions []models.SSHSession
	if err := c.get(ctx, path, &sessions); err != nil {
		return nil, err
	}
	return sessions, nil
}
