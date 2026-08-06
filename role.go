// Copyright 2026 The k8shell Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package k8shell

import (
	"context"

	"github.com/k8shell-io/common/pkg/models"
)

// ListRoles returns the roles assignable within org: those scoped to it plus
// all global roles.
func (c *Client) ListRoles(ctx context.Context, org string) ([]models.RoleInfo, error) {
	var roles []models.RoleInfo
	if err := c.get(ctx, "/api/v1/organizations/"+org+"/roles", &roles); err != nil {
		return nil, err
	}
	return roles, nil
}

// GetRole returns the named role scoped to org (or a global role visible
// within it). The server has no single-role lookup endpoint, so this filters
// the result of ListRoles client-side.
func (c *Client) GetRole(ctx context.Context, org, name string) (*models.RoleInfo, error) {
	roles, err := c.ListRoles(ctx, org)
	if err != nil {
		return nil, err
	}
	for _, r := range roles {
		if r.Name == name {
			return &r, nil
		}
	}
	return nil, &APIError{StatusCode: 404, Message: "role not found"}
}

// CreateRole registers a new assignable role scoped to org and returns it.
// Global roles cannot be created through this method.
func (c *Client) CreateRole(ctx context.Context, org string, req models.RoleCreateRequest) (*models.RoleInfo, error) {
	var role models.RoleInfo
	if err := c.post(ctx, "/api/v1/organizations/"+org+"/roles", req, &role); err != nil {
		return nil, err
	}
	return &role, nil
}

// UpdateRole updates a role's description and returns the updated record.
// Name and org are immutable. Global roles cannot be updated through this method.
func (c *Client) UpdateRole(ctx context.Context, org, name string, req models.RoleUpdateRequest) (*models.RoleInfo, error) {
	var role models.RoleInfo
	if err := c.patch(ctx, "/api/v1/organizations/"+org+"/roles/"+name, req, &role); err != nil {
		return nil, err
	}
	return &role, nil
}

// DeleteRole removes a role from the registry. Fails if any user still holds
// the role. Global roles cannot be removed through this method.
func (c *Client) DeleteRole(ctx context.Context, org, name string) error {
	return c.delete(ctx, "/api/v1/organizations/"+org+"/roles/"+name)
}

// AddRoleBlueprints grants a role one or more blueprints, in addition to any
// existing ones; every user holding the role gains access to them.
func (c *Client) AddRoleBlueprints(ctx context.Context, org, name string, blueprints []string) error {
	return c.post(ctx, "/api/v1/organizations/"+org+"/roles/"+name+"/blueprints", models.RoleBlueprintsRequest{Blueprints: blueprints}, nil)
}

// RemoveRoleBlueprints revokes one or more blueprints from a role, leaving others untouched.
func (c *Client) RemoveRoleBlueprints(ctx context.Context, org, name string, blueprints []string) error {
	return c.deleteWithBody(ctx, "/api/v1/organizations/"+org+"/roles/"+name+"/blueprints", models.RoleBlueprintsRequest{Blueprints: blueprints})
}
