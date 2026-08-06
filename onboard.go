// Copyright 2026 The k8shell Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package k8shell

import (
	"context"
	"strconv"

	"github.com/k8shell-io/common/pkg/models"
)

// OnboardRuleFilter narrows the results of ListOnboardRules. Zero values
// impose no restriction on that field.
type OnboardRuleFilter struct {
	IDP    string
	Status string
	Action string
}

// queryCondition is the outgoing wire shape of a single filter condition in
// a query payload, matching models.QueryCondition's JSON shape. That type
// only implements UnmarshalJSON (for parsing responses from a _schema
// endpoint) and has no json tags of its own, so it can't be used to marshal
// a request body — this local type fills that gap.
type queryCondition struct {
	Field string   `json:"field"`
	Op    string   `json:"op"`
	Value []string `json:"value"`
}

// queryFilters is the outgoing wire shape of a query payload's filter group,
// matching models.QueryFilters but using queryCondition for its conditions.
type queryFilters struct {
	Op         string           `json:"op"`
	Conditions []queryCondition `json:"conditions"`
}

// queryPayload is the outgoing wire shape of a client-issued query, matching
// models.QueryPayload. Only Filters is populated here; sort/paging use the
// resource's own defaults.
type queryPayload struct {
	Filters *queryFilters `json:"filters,omitempty"`
}

// ListOnboardRules returns the onboard rules scoped to org, optionally
// narrowed by filter, via the resource's _query endpoint (there is no plain
// list endpoint for onboard rules). Passing action="waitlist" via filter is
// how a caller renders the pending approval queue — there is no separate
// endpoint for that.
func (c *Client) ListOnboardRules(ctx context.Context, org string, filter OnboardRuleFilter) ([]models.OnboardRule, error) {
	var conditions []queryCondition
	if filter.IDP != "" {
		conditions = append(conditions, queryCondition{Field: "idp", Op: "eq", Value: []string{filter.IDP}})
	}
	if filter.Status != "" {
		conditions = append(conditions, queryCondition{Field: "status", Op: "eq", Value: []string{filter.Status}})
	}
	if filter.Action != "" {
		conditions = append(conditions, queryCondition{Field: "action", Op: "eq", Value: []string{filter.Action}})
	}

	var payload queryPayload
	if len(conditions) > 0 {
		payload.Filters = &queryFilters{Op: "and", Conditions: conditions}
	}

	var rules []models.OnboardRule
	if err := c.post(ctx, "/api/v1/organizations/"+org+"/onboard-rules/_query", payload, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// CreateOnboardRule registers a new onboard rule scoped to org — a standing
// pattern policy, or a one-off decision for a specific username — and returns it.
func (c *Client) CreateOnboardRule(ctx context.Context, org string, req models.OnboardRuleCreateRequest) (*models.OnboardRule, error) {
	var rule models.OnboardRule
	if err := c.post(ctx, "/api/v1/organizations/"+org+"/onboard-rules", req, &rule); err != nil {
		return nil, err
	}
	return &rule, nil
}

// UpdateOnboardRule fully replaces the mutable fields of an onboard rule and
// returns the updated record. idp/usernamePattern/org are immutable — delete
// and recreate the rule to change them.
func (c *Client) UpdateOnboardRule(ctx context.Context, org string, id int32, req models.OnboardRuleUpdateRequest) (*models.OnboardRule, error) {
	var rule models.OnboardRule
	if err := c.patch(ctx, "/api/v1/organizations/"+org+"/onboard-rules/"+strconv.Itoa(int(id)), req, &rule); err != nil {
		return nil, err
	}
	return &rule, nil
}

// DeleteOnboardRule removes an onboard rule from the registry.
func (c *Client) DeleteOnboardRule(ctx context.Context, org string, id int32) error {
	return c.delete(ctx, "/api/v1/organizations/"+org+"/onboard-rules/"+strconv.Itoa(int(id)))
}

// ApproveOnboardRule approves a pending ("waitlist") onboard rule, flipping
// its action to "allow", and immediately onboards the user it names rather
// than waiting for their next login attempt.
func (c *Client) ApproveOnboardRule(ctx context.Context, org string, id int32) (*models.User, error) {
	var u models.User
	if err := c.post(ctx, "/api/v1/organizations/"+org+"/onboard-rules/"+strconv.Itoa(int(id))+"/approve", struct{}{}, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// RejectOnboardRule rejects a pending ("waitlist") onboard rule, flipping its
// action to "reject" so the user cannot re-trigger a new waitlist entry by
// trying again, and returns the updated rule.
func (c *Client) RejectOnboardRule(ctx context.Context, org string, id int32, req models.OnboardRuleRejectRequest) (*models.OnboardRule, error) {
	var rule models.OnboardRule
	if err := c.post(ctx, "/api/v1/organizations/"+org+"/onboard-rules/"+strconv.Itoa(int(id))+"/reject", req, &rule); err != nil {
		return nil, err
	}
	return &rule, nil
}
