// Copyright 2026 The k8shell Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package k8shell

import (
	"context"

	"github.com/k8shell-io/common/pkg/models"
)

// ComposeBlueprint submits a k8shell file for the named user and returns the
// blueprint composed by merging it with the user's assigned blueprints.
// Only admin tokens, or the user themself, may compose their own file.
func (c *Client) ComposeBlueprint(ctx context.Context, username string, k8shellFile *models.K8shellFile) (*models.Blueprint, error) {
	var bp models.Blueprint
	if err := c.postYAML(ctx, c.userPath(username)+"/blueprints/compose", k8shellFile, &bp); err != nil {
		return nil, err
	}
	return &bp, nil
}
