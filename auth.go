// Copyright 2026 The k8shell Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package k8shell

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/k8shell-io/common/pkg/models"
)

type providerInfo struct {
	Name         string   `json:"name"`
	Capabilities []string `json:"capabilities"`
}

// ListProviders returns the names of identity providers that support the
// OnboardUserWebFlow capability (i.e. browser-based login).
func (c *Client) ListProviders() ([]string, error) {
	var providers []providerInfo
	if err := c.get("/api/v1/auth/providers", &providers); err != nil {
		return nil, err
	}
	var names []string
	for _, p := range providers {
		for _, cap := range p.Capabilities {
			if cap == "OnboardUserWebFlow" {
				names = append(names, p.Name)
				break
			}
		}
	}
	return names, nil
}

// PollToken checks whether the PAT for the given OAuth state is ready.
// Returns (nil, nil) when the login is still pending (202 Accepted),
// or (token, nil) once the token is issued (200 OK).
func (c *Client) PollToken(state string) (*models.UserToken, error) {
	u, err := url.Parse(c.server + "/api/v1/auth/token")
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("state", state)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	if c.debug {
		c.debugRequest(req)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if c.debug {
		c.debugResponse(resp)
	}

	if resp.StatusCode == http.StatusAccepted {
		return nil, nil
	}
	if resp.StatusCode >= 400 {
		apiErr := &APIError{StatusCode: resp.StatusCode}
		var body struct {
			Msg string `json:"msg"`
		}
		if json.NewDecoder(resp.Body).Decode(&body) == nil && body.Msg != "" {
			apiErr.Message = body.Msg
		}
		return nil, apiErr
	}
	var token models.UserToken
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, err
	}
	return &token, nil
}
