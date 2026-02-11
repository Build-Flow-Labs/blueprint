package webhook

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
)

// WebhookEvent represents the top-level workflow_run webhook payload.
type WebhookEvent struct {
	Action      string      `json:"action"`
	WorkflowRun RunPayload  `json:"workflow_run"`
	Repository  RepoPayload `json:"repository"`
}

// RunPayload is the workflow_run object within the webhook event.
type RunPayload struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	HeadSHA    string `json:"head_sha"`
	HeadBranch string `json:"head_branch"`
	Path       string `json:"path"`
	Event      string `json:"event"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	Actor      struct {
		Login string `json:"login"`
	} `json:"actor"`
}

// RepoPayload is the repository object within the webhook event.
type RepoPayload struct {
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	Owner    struct {
		Login string `json:"login"`
	} `json:"owner"`
}

// handleWebhook processes incoming GitHub webhook POST requests.
func (s *Server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read body (limit 10MB)
	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	if err != nil {
		s.logger.Error("failed to read request body", "error", err)
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	// Verify signature
	sig := r.Header.Get("X-Hub-Signature-256")
	if err := VerifySignature(body, sig, s.cfg.WebhookSecret); err != nil {
		s.logger.Warn("signature verification failed", "error", err)
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	// Check event type
	eventType := r.Header.Get("X-GitHub-Event")
	if eventType != "workflow_run" {
		s.logger.Debug("ignoring non-workflow_run event", "type", eventType)
		w.WriteHeader(http.StatusOK)
		return
	}

	// Parse event
	var event WebhookEvent
	if err := json.Unmarshal(body, &event); err != nil {
		s.logger.Error("failed to parse webhook payload", "error", err)
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	// Only process completed runs
	if event.Action != "completed" {
		s.logger.Debug("ignoring non-completed action", "action", event.Action)
		w.WriteHeader(http.StatusOK)
		return
	}

	// Skip PBOM Collector runs to prevent infinite enrichment loops
	if event.WorkflowRun.Name == "PBOM Collector" {
		s.logger.Debug("skipping PBOM Collector run",
			"repo", event.Repository.FullName,
			"run_id", event.WorkflowRun.ID,
		)
		w.WriteHeader(http.StatusOK)
		return
	}

	s.logger.Info("processing workflow_run.completed",
		"repo", event.Repository.FullName,
		"workflow", event.WorkflowRun.Name,
		"run_id", event.WorkflowRun.ID,
		"conclusion", event.WorkflowRun.Conclusion,
		slog.String("sha", event.WorkflowRun.HeadSHA[:8]),
	)

	// Dispatch enrichment asynchronously — respond 202 immediately
	go s.enricher.Enrich(r.Context(), event)

	w.WriteHeader(http.StatusAccepted)
}
