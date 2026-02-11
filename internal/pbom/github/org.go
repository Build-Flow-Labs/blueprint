package github

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// GetOrg fetches organization details (validates access and checks plan).
func (c *Client) GetOrg(ctx context.Context, org string) (*Org, error) {
	path := fmt.Sprintf("/orgs/%s", org)
	data, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	var o Org
	if err := json.Unmarshal(data, &o); err != nil {
		return nil, fmt.Errorf("parsing org: %w", err)
	}
	return &o, nil
}

// GetTokenScopes returns the OAuth scopes of the current token by inspecting
// the X-OAuth-Scopes response header from an authenticated request.
func (c *Client) GetTokenScopes(ctx context.Context) ([]string, error) {
	_, headers, err := c.getWithHeaders(ctx, "/user")
	if err != nil {
		return nil, err
	}
	scopeHeader := headers.Get("X-OAuth-Scopes")
	if scopeHeader == "" {
		return nil, nil
	}
	parts := strings.Split(scopeHeader, ",")
	scopes := make([]string, 0, len(parts))
	for _, p := range parts {
		s := strings.TrimSpace(p)
		if s != "" {
			scopes = append(scopes, s)
		}
	}
	return scopes, nil
}

// CreateCustomProperty creates or updates an org-level custom property.
// Uses PUT which is idempotent (safe to re-run).
func (c *Client) CreateCustomProperty(ctx context.Context, org, name string, prop CustomPropertyDef) error {
	path := fmt.Sprintf("/orgs/%s/properties/schema/%s", org, name)
	_, err := c.put(ctx, path, prop)
	return err
}

// ListRepos lists repositories in an organization.
func (c *Client) ListRepos(ctx context.Context, org string) ([]Repo, error) {
	var all []Repo
	page := 1
	for {
		path := fmt.Sprintf("/orgs/%s/repos?per_page=100&page=%d", org, page)
		data, err := c.get(ctx, path)
		if err != nil {
			return nil, err
		}
		var repos []Repo
		if err := json.Unmarshal(data, &repos); err != nil {
			return nil, fmt.Errorf("parsing repos: %w", err)
		}
		if len(repos) == 0 {
			break
		}
		all = append(all, repos...)
		page++
	}
	return all, nil
}

// SetRepoCustomProperties batch-sets custom property values on repositories.
func (c *Client) SetRepoCustomProperties(ctx context.Context, org string, repoNames []string, properties map[string]string) error {
	props := make([]PropertyKV, 0, len(properties))
	for k, v := range properties {
		props = append(props, PropertyKV{PropertyName: k, Value: v})
	}
	payload := RepoPropertyValues{
		RepositoryNames: repoNames,
		Properties:      props,
	}
	path := fmt.Sprintf("/orgs/%s/properties/values", org)
	_, err := c.patch(ctx, path, payload)
	return err
}

// GetFileContents gets a file's content and SHA from a repo (for update operations).
func (c *Client) GetFileContents(ctx context.Context, owner, repo, filePath string) (*FileContent, error) {
	path := fmt.Sprintf("/repos/%s/%s/contents/%s", owner, repo, filePath)
	data, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	var fc FileContent
	if err := json.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("parsing file content: %w", err)
	}
	return &fc, nil
}

// CreateOrUpdateFileContents creates or updates a file in a repo via the Contents API.
// If sha is non-empty, the file is updated; otherwise it is created.
func (c *Client) CreateOrUpdateFileContents(ctx context.Context, owner, repo, filePath, message, content, sha string) error {
	path := fmt.Sprintf("/repos/%s/%s/contents/%s", owner, repo, filePath)
	payload := FileContentRequest{
		Message: message,
		Content: content,
		SHA:     sha,
	}
	_, err := c.put(ctx, path, payload)
	return err
}

// CreateOrgWebhook creates an organization-level webhook.
func (c *Client) CreateOrgWebhook(ctx context.Context, org string, hook WebhookConfig) (*WebhookResponse, error) {
	path := fmt.Sprintf("/orgs/%s/hooks", org)
	data, err := c.post(ctx, path, hook)
	if err != nil {
		return nil, err
	}
	var resp WebhookResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parsing webhook response: %w", err)
	}
	return &resp, nil
}

// ListOrgWebhooks lists existing organization webhooks (for idempotency checks).
func (c *Client) ListOrgWebhooks(ctx context.Context, org string) ([]WebhookResponse, error) {
	path := fmt.Sprintf("/orgs/%s/hooks", org)
	data, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	var hooks []WebhookResponse
	if err := json.Unmarshal(data, &hooks); err != nil {
		return nil, fmt.Errorf("parsing webhooks: %w", err)
	}
	return hooks, nil
}
