// Copyright 2026 The k8shell Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package k8shell

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/k8shell-io/common/pkg/models"
)

// WorkspaceCreateRequest is the payload for creating a workspace.
// Either Blueprint or (RepoOwner + RepoName) must be set.
type WorkspaceCreateRequest struct {
	Username  string `json:"username"`
	Blueprint string `json:"blueprint,omitempty"`
	RepoOwner string `json:"repoOwner,omitempty"`
	RepoName  string `json:"repoName,omitempty"`
	RepoRef   string `json:"repoRef,omitempty"`
}

// WorkspaceCreateResponse is the 202 Accepted body returned by CreateWorkspace.
type WorkspaceCreateResponse struct {
	Workspace  string `json:"workspace"`
	JobID      string `json:"jobId"`
	MonitorURL string `json:"monitorUrl"`
}

// ListWorkspaces returns workspaces visible to the authenticated token.
// When username is non-empty the results are filtered by owner.
// When all is true, workspaces in all states are included.
func (c *Client) ListWorkspaces(ctx context.Context, username string, all bool) ([]models.WorkspaceDetails, error) {
	q := url.Values{}
	if username != "" {
		q.Set("username", username)
	}
	if all {
		q.Set("all", "true")
	}
	path := "/api/v1/workspaces"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var workspaces []models.WorkspaceDetails
	if err := c.get(ctx, path, &workspaces); err != nil {
		return nil, err
	}
	return workspaces, nil
}

// CreateWorkspace submits a workspace creation request and returns the 202 response
// containing the workspace name, job ID, and SSE monitor URL.
func (c *Client) CreateWorkspace(ctx context.Context, req WorkspaceCreateRequest) (*WorkspaceCreateResponse, error) {
	var resp WorkspaceCreateResponse
	if err := c.post(ctx, "/api/v1/workspaces", req, &resp); err != nil {
		return nil, err
	}
	// Strip a duplicated jobId segment that some server versions emit in monitorUrl.
	if resp.JobID != "" && strings.Count(resp.MonitorURL, resp.JobID) > 1 {
		if idx := strings.LastIndex(resp.MonitorURL, "/"+resp.JobID); idx >= 0 {
			resp.MonitorURL = resp.MonitorURL[:idx]
		}
	}
	return &resp, nil
}

// GetWorkspace returns the details of the named workspace.
func (c *Client) GetWorkspace(ctx context.Context, name string) (*models.WorkspaceDetails, error) {
	var ws models.WorkspaceDetails
	if err := c.get(ctx, "/api/v1/workspaces/"+name, &ws); err != nil {
		return nil, err
	}
	return &ws, nil
}

// DeleteWorkspace shuts down the named workspace.
// When deleteData is true, workspace storage is permanently deleted.
func (c *Client) DeleteWorkspace(ctx context.Context, name string, deleteData bool) error {
	path := "/api/v1/workspaces/" + name
	if deleteData {
		path += "?delete=true"
	}
	return c.delete(ctx, path)
}

// MonitorWorkspace opens an SSE stream at monitorURL and returns the response
// body for the caller to consume. monitorURL may be a full URL or a path
// relative to the client's server. The caller is responsible for closing the
// returned ReadCloser.
func (c *Client) MonitorWorkspace(ctx context.Context, monitorURL string) (io.ReadCloser, error) {
	if u, err := url.Parse(monitorURL); err == nil && u.Scheme == "" {
		monitorURL = c.server + monitorURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, monitorURL, nil)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "text/event-stream")
	if c.debug {
		c.debugRequest(req)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if c.debug {
		c.debugResponse(resp)
	}
	if resp.StatusCode >= 400 {
		resp.Body.Close()
		return nil, &APIError{StatusCode: resp.StatusCode}
	}
	return resp.Body, nil
}
