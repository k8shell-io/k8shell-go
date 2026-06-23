// Copyright 2026 The k8shell Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package k8shell

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
)

// Client is an authenticated HTTP client for the k8shell API.
type Client struct {
	server string
	token  string
	debug  bool
	debugw io.Writer
	http   *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithDebug enables request/response header logging.
func WithDebug() Option {
	return func(c *Client) { c.debug = true }
}

// WithDebugWriter sets the writer used for debug output and implies [WithDebug].
func WithDebugWriter(w io.Writer) Option {
	return func(c *Client) {
		c.debug = true
		c.debugw = w
	}
}

// WithInsecure disables TLS certificate verification.
func WithInsecure() Option {
	return func(c *Client) {
		c.http.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		}
	}
}

// New creates an authenticated Client for the given server URL and PAT token.
func New(server, token string, opts ...Option) *Client {
	c := &Client{
		server: server,
		token:  token,
		http:   &http.Client{},
		debugw: os.Stderr,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// NewAnonymous creates an unauthenticated Client, useful for the browser login flow.
func NewAnonymous(server string, opts ...Option) *Client {
	return New(server, "", opts...)
}

// APIError is returned for non-2xx responses and carries the HTTP status code
// and an optional message from the response body.
type APIError struct {
	StatusCode int
	Message    string
	cause      error
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	switch e.StatusCode {
	case http.StatusUnauthorized:
		return "unauthorized — verify your PAT token"
	case http.StatusForbidden:
		return "access denied"
	case http.StatusNotFound:
		return "not found"
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable:
		return fmt.Sprintf("server error (%d)", e.StatusCode)
	default:
		return fmt.Sprintf("request failed (%d)", e.StatusCode)
	}
}

// Unwrap returns the underlying cause, enabling errors.Is/errors.As traversal.
func (e *APIError) Unwrap() error { return e.cause }

func (c *Client) maskToken() string {
	if len(c.token) <= 6 {
		return "***"
	}
	return c.token[:6] + "***"
}

func (c *Client) debugRequest(req *http.Request) {
	fmt.Fprintf(c.debugw, "> %s %s\n", req.Method, req.URL)
	keys := make([]string, 0, len(req.Header))
	for k := range req.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := req.Header.Get(k)
		if k == "Authorization" {
			v = "Bearer " + c.maskToken()
		}
		fmt.Fprintf(c.debugw, "> %s: %s\n", k, v)
	}
	fmt.Fprintln(c.debugw, ">")
}

func (c *Client) debugResponse(resp *http.Response) {
	fmt.Fprintf(c.debugw, "< %s\n", resp.Status)
	keys := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(c.debugw, "< %s: %s\n", k, resp.Header.Get(k))
	}
	fmt.Fprintln(c.debugw, "<")
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.server+path, nil)
	if err != nil {
		return err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/json")
	if c.debug {
		c.debugRequest(req)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if c.debug {
		c.debugResponse(resp)
	}
	if resp.StatusCode >= 400 {
		return &APIError{StatusCode: resp.StatusCode}
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) post(ctx context.Context, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.server+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.debug {
		c.debugRequest(req)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if c.debug {
		c.debugResponse(resp)
	}
	if resp.StatusCode >= 400 {
		return &APIError{StatusCode: resp.StatusCode}
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *Client) delete(ctx context.Context, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.server+path, nil)
	if err != nil {
		return err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.debug {
		c.debugRequest(req)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if c.debug {
		c.debugResponse(resp)
	}
	if resp.StatusCode >= 400 {
		return &APIError{StatusCode: resp.StatusCode}
	}
	return nil
}

// userPath returns the API base path for a user-scoped resource.
// An empty username resolves to /api/v1/me (the token's own user).
func (c *Client) userPath(username string) string {
	if username == "" {
		return "/api/v1/me"
	}
	return "/api/v1/users/" + username
}
