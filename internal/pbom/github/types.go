package github

import "time"

// WorkflowRun represents a GitHub Actions workflow run.
type WorkflowRun struct {
	ID           int64     `json:"id"`
	Name         string    `json:"name"`
	HeadSHA      string    `json:"head_sha"`
	HeadBranch   string    `json:"head_branch"`
	Path         string    `json:"path"`
	DisplayTitle string    `json:"display_title"`
	Event        string    `json:"event"`
	Status       string    `json:"status"`
	Conclusion   string    `json:"conclusion"`
	WorkflowID   int64     `json:"workflow_id"`
	Actor        Actor     `json:"actor"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	RunStartedAt time.Time `json:"run_started_at"`
	Repository   Repo      `json:"repository"`
}

// WorkflowRunsResponse represents the list runs API response.
type WorkflowRunsResponse struct {
	TotalCount   int           `json:"total_count"`
	WorkflowRuns []WorkflowRun `json:"workflow_runs"`
}

// Actor represents a GitHub user.
type Actor struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
}

// Repo represents a GitHub repository (minimal fields).
type Repo struct {
	ID       int64 `json:"id"`
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	Owner    Owner  `json:"owner"`
}

// Owner represents a repository owner.
type Owner struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
}

// JobsResponse represents the list jobs API response.
type JobsResponse struct {
	TotalCount int   `json:"total_count"`
	Jobs       []Job `json:"jobs"`
}

// Job represents a single job within a workflow run.
type Job struct {
	ID              int64     `json:"id"`
	RunID           int64     `json:"run_id"`
	Name            string    `json:"name"`
	Status          string    `json:"status"`
	Conclusion      string    `json:"conclusion"`
	StartedAt       time.Time `json:"started_at"`
	CompletedAt     time.Time `json:"completed_at"`
	Labels          []string  `json:"labels"`
	RunnerName      string    `json:"runner_name"`
	RunnerID        int64     `json:"runner_id"`
	RunnerGroupName string    `json:"runner_group_name"`
	Steps           []Step    `json:"steps"`
}

// Step represents a single step within a job.
type Step struct {
	Name        string    `json:"name"`
	Number      int       `json:"number"`
	Status      string    `json:"status"`
	Conclusion  string    `json:"conclusion"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
}

// ArtifactsResponse represents the list artifacts API response.
type ArtifactsResponse struct {
	TotalCount int        `json:"total_count"`
	Artifacts  []Artifact `json:"artifacts"`
}

// Artifact represents a workflow run artifact.
type Artifact struct {
	ID                 int64     `json:"id"`
	Name               string    `json:"name"`
	SizeInBytes        int64     `json:"size_in_bytes"`
	ArchiveDownloadURL string    `json:"archive_download_url"`
	Digest             string    `json:"digest"`
	CreatedAt          time.Time `json:"created_at"`
	ExpiresAt          time.Time `json:"expires_at"`
}

// FileContent represents a file fetched via the Contents API.
type FileContent struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
	Path     string `json:"path"`
	SHA      string `json:"sha"`
}

// LanguagesResponse maps language names to byte counts.
// Returned by GET /repos/{owner}/{repo}/languages.
type LanguagesResponse map[string]int64

// AttestationsResponse represents the GET /repos/{owner}/{repo}/attestations/{digest} response.
type AttestationsResponse struct {
	Attestations []AttestationBundle `json:"attestations"`
}

// AttestationBundle wraps a single attestation entry.
type AttestationBundle struct {
	Bundle BundlePayload `json:"bundle"`
}

// BundlePayload contains the DSSE envelope and verification material.
type BundlePayload struct {
	MediaType    string        `json:"mediaType"`
	DSSEEnvelope *DSSEEnvelope `json:"dsseEnvelope"`
}

// DSSEEnvelope is the Dead Simple Signing Envelope.
type DSSEEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []DSSESignature `json:"signatures"`
}

// DSSESignature is a single signature in the envelope.
type DSSESignature struct {
	Sig string `json:"sig"`
}

// Org represents a GitHub organization.
type Org struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
	Plan  struct {
		Name string `json:"name"`
	} `json:"plan"`
}

// CustomPropertyDef defines an org-level custom property.
type CustomPropertyDef struct {
	ValueType     string   `json:"value_type"`
	Required      bool     `json:"required"`
	DefaultValue  *string  `json:"default_value,omitempty"`
	Description   string   `json:"description,omitempty"`
	AllowedValues []string `json:"allowed_values,omitempty"`
}

// WebhookConfig is the payload to create an org webhook.
type WebhookConfig struct {
	Name   string          `json:"name"`
	Active bool            `json:"active"`
	Events []string        `json:"events"`
	Config WebhookEndpoint `json:"config"`
}

// WebhookEndpoint is the endpoint config for a webhook.
type WebhookEndpoint struct {
	URL         string `json:"url"`
	ContentType string `json:"content_type"`
	Secret      string `json:"secret,omitempty"`
	InsecureSSL string `json:"insecure_ssl"`
}

// WebhookResponse is the response from creating/listing webhooks.
type WebhookResponse struct {
	ID     int64           `json:"id"`
	Active bool            `json:"active"`
	Events []string        `json:"events"`
	Config WebhookEndpoint `json:"config"`
}

// RepoPropertyValues is used for batch-setting custom property values.
type RepoPropertyValues struct {
	RepositoryNames []string       `json:"repository_names"`
	Properties      []PropertyKV   `json:"properties"`
}

// PropertyKV is a key-value pair for custom properties.
type PropertyKV struct {
	PropertyName string `json:"property_name"`
	Value        string `json:"value"`
}

// FileContentRequest is the payload to create/update a file via Contents API.
type FileContentRequest struct {
	Message string `json:"message"`
	Content string `json:"content"`
	SHA     string `json:"sha,omitempty"`
}
