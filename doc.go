// Copyright 2026 The k8shell Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package k8shell provides a Go client for the k8shell API.
//
// Create an authenticated client with a server URL and personal access token:
//
//	c := k8shell.New("https://k8shell.example.com", token)
//	ws, err := c.ListWorkspaces(ctx, "", false)
//
// For browser-based login, use [NewAnonymous] to perform the OAuth web flow
// without a token, then construct an authenticated client from the returned PAT.
package k8shell
