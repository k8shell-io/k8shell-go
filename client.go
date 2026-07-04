// Copyright 2026 The k8shell Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package k8shell

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
)

// ErrDryRun is returned by request methods instead of performing the HTTP
// call when the client was constructed with [WithCurl]: the equivalent curl
// command has already been printed and the request is intentionally not
// sent, so no response data is available. Callers should propagate this
// error rather than act on zero-value results.
var ErrDryRun = errors.New("dry run: request not sent (--curl)")

// Client is an authenticated HTTP client for the k8shell API.
type Client struct {
	server       string
	token        string
	debug        bool
	curl         bool
	curlVerbose  bool
	curlLocation bool
	insecure     bool
	debugw       io.Writer
	http         *http.Client
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

// WithCurl enables printing an equivalent curl command — including the
// unmasked bearer token — for every request instead of debug header output.
// Callers are responsible for not combining this with [WithDebug].
func WithCurl() Option {
	return func(c *Client) { c.curl = true }
}

// WithCurlVerbose adds curl's own -v flag to the command printed by
// [WithCurl], so curl prints its own verbose connection/handshake details
// when the command is run. Has no effect unless [WithCurl] is also set.
func WithCurlVerbose() Option {
	return func(c *Client) { c.curlVerbose = true }
}

// WithCurlLocation adds curl's own -L flag to the command printed by
// [WithCurl], so curl follows redirects the same way c.http does by
// default. Has no effect unless [WithCurl] is also set.
func WithCurlLocation() Option {
	return func(c *Client) { c.curlLocation = true }
}

// WithInsecure disables TLS certificate verification.
func WithInsecure() Option {
	return func(c *Client) {
		c.insecure = true
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

// apiErrorBody is the API's error response shape: {"status": <code>, "msg": "..."}.
type apiErrorBody struct {
	Status int    `json:"status"`
	Msg    string `json:"msg"`
}

// newAPIError builds an APIError from a non-2xx response, extracting the message
// from the response body when one is present.
func newAPIError(resp *http.Response) *APIError {
	apiErr := &APIError{StatusCode: resp.StatusCode}
	body, err := io.ReadAll(resp.Body)
	if err != nil || len(body) == 0 {
		return apiErr
	}
	var eb apiErrorBody
	if json.Unmarshal(body, &eb) == nil && eb.Msg != "" {
		apiErr.Message = eb.Msg
	} else {
		apiErr.Message = strings.TrimSpace(string(body))
	}
	return apiErr
}

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

// printCurl writes a curl command reproducing req, including the unmasked
// bearer token, so the request can be replayed outside the CLI. Unlike debug
// output, this is written to stdout (not c.debugw) so it can be piped
// directly into a shell, e.g. `k8shell ... --curl | bash`.
func (c *Client) printCurl(req *http.Request, body []byte) {
	var b strings.Builder
	b.WriteString("curl")
	if c.curlVerbose {
		b.WriteString(" -v")
	}
	if c.curlLocation {
		b.WriteString(" -L")
	}
	fmt.Fprintf(&b, " -X %s", req.Method)
	if c.insecure {
		b.WriteString(" -k")
	}
	fmt.Fprintf(&b, " %s", shellQuote(req.URL.String()))
	keys := make([]string, 0, len(req.Header))
	for k := range req.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, " \\\n  -H %s", shellQuote(k+": "+req.Header.Get(k)))
	}
	if len(body) > 0 {
		fmt.Fprintf(&b, " \\\n  -d %s", shellQuote(string(body)))
	}
	fmt.Fprintln(os.Stdout, b.String())
}

// shellQuote wraps s in single quotes, escaping any embedded single quotes
// so the result is safe to paste into a POSIX shell.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
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
	if c.curl {
		c.printCurl(req, nil)
		return ErrDryRun
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
		return newAPIError(resp)
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
	if c.curl {
		c.printCurl(req, b)
		return ErrDryRun
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
		return newAPIError(resp)
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *Client) patch(ctx context.Context, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, c.server+path, bytes.NewReader(b))
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
	if c.curl {
		c.printCurl(req, b)
		return ErrDryRun
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
		return newAPIError(resp)
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *Client) put(ctx context.Context, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.server+path, bytes.NewReader(b))
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
	if c.curl {
		c.printCurl(req, b)
		return ErrDryRun
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
		return newAPIError(resp)
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
	if c.curl {
		c.printCurl(req, nil)
		return ErrDryRun
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
		return newAPIError(resp)
	}
	return nil
}

func (c *Client) deleteWithBody(ctx context.Context, path string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.server+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.debug {
		c.debugRequest(req)
	}
	if c.curl {
		c.printCurl(req, b)
		return ErrDryRun
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
		return newAPIError(resp)
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
