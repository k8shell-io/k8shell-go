// Copyright 2026 The k8shell Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package k8shell

import (
	"context"

	"github.com/k8shell-io/common/pkg/models"
)

// ListOrganizations returns the registered organizations.
func (c *Client) ListOrganizations(ctx context.Context) ([]models.Organization, error) {
	var orgs []models.Organization
	if err := c.get(ctx, "/api/v1/organizations", &orgs); err != nil {
		return nil, err
	}
	return orgs, nil
}

// GetOrganization returns a single organization by name.
func (c *Client) GetOrganization(ctx context.Context, name string) (*models.Organization, error) {
	var org models.Organization
	if err := c.get(ctx, "/api/v1/organizations/"+name, &org); err != nil {
		return nil, err
	}
	return &org, nil
}

// CreateOrganization registers a new organization and returns it.
func (c *Client) CreateOrganization(ctx context.Context, req models.OrganizationCreateRequest) (*models.Organization, error) {
	var org models.Organization
	if err := c.post(ctx, "/api/v1/organizations", req, &org); err != nil {
		return nil, err
	}
	return &org, nil
}

// UpdateOrganization applies a partial update to an organization's description
// and returns the updated record. The name is immutable and cannot be changed.
func (c *Client) UpdateOrganization(ctx context.Context, name string, req models.OrganizationUpdateRequest) (*models.Organization, error) {
	var org models.Organization
	if err := c.patch(ctx, "/api/v1/organizations/"+name, req, &org); err != nil {
		return nil, err
	}
	return &org, nil
}

// DeleteOrganization removes an organization from the registry. req controls
// what happens to the organization's users and their workspaces — see
// models.OrganizationDeleteRequest.
func (c *Client) DeleteOrganization(ctx context.Context, name string, req models.OrganizationDeleteRequest) error {
	return c.deleteWithBody(ctx, "/api/v1/organizations/"+name, req)
}
