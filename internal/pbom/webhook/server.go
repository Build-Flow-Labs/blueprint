package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/build-flow-labs/blueprint/internal/pbom/dashboard"
	gh "github.com/build-flow-labs/blueprint/internal/pbom/github"
)

// Config holds webhook server configuration.
type Config struct {
	Addr          string
	WebhookSecret string
	GitHubToken   string
	StorageDir    string
}

// Server is the webhook HTTP server.
type Server struct {
	cfg       Config
	ghClient  *gh.Client
	enricher  *Enricher
	dashboard *dashboard.Dashboard
	logger    *slog.Logger
	mux       *http.ServeMux

	eventsProcessed atomic.Int64
	lastEventAt     atomic.Value // time.Time
}

// NewServer creates a configured webhook server.
func NewServer(cfg Config, logger *slog.Logger) *Server {
	ghClient := gh.NewClient(cfg.GitHubToken)
	enricher := NewEnricher(ghClient, cfg.StorageDir, logger)

	// Initialize dashboard
	dash, err := dashboard.New(cfg.StorageDir, logger)
	if err != nil {
		logger.Warn("dashboard init failed, UI will be unavailable", "error", err)
	} else {
		// Wire enricher to refresh dashboard on new PBOMs
		enricher.onStore = dash.Refresh
	}

	s := &Server{
		cfg:       cfg,
		ghClient:  ghClient,
		enricher:  enricher,
		dashboard: dash,
		logger:    logger,
		mux:       http.NewServeMux(),
	}

	s.mux.HandleFunc("/webhook", s.handleWebhook)
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/status", s.handleStatus)

	// Register dashboard routes
	if dash != nil {
		dash.RegisterRoutes(s.mux)
		logger.Info("dashboard enabled", "url", fmt.Sprintf("http://localhost%s/ui", cfg.Addr))
	}

	return s
}

// Start begins listening for webhook events. Blocks until context is cancelled.
func (s *Server) Start(ctx context.Context) error {
	srv := &http.Server{
		Addr:         s.cfg.Addr,
		Handler:      s.mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("webhook listener starting",
			"addr", s.cfg.Addr,
			"storage_dir", s.cfg.StorageDir,
		)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	case <-ctx.Done():
		s.logger.Info("shutting down webhook listener")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "ok")
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]any{
		"events_processed": s.eventsProcessed.Load(),
	}
	if t, ok := s.lastEventAt.Load().(time.Time); ok {
		status["last_event_at"] = t.Format(time.RFC3339)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}
