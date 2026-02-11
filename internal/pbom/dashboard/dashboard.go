package dashboard

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/build-flow-labs/blueprint/pbom/schema"
)

//go:embed templates/* static/*
var embeddedFS embed.FS

// Dashboard serves the web UI for viewing PBOMs.
type Dashboard struct {
	index       *Index
	overviewTmpl *template.Template
	detailTmpl   *template.Template
	partialsTmpl *template.Template
	staticFS     fs.FS
	logger       *slog.Logger
}

// New creates a Dashboard, loads templates, and indexes existing PBOMs.
func New(storageDir string, logger *slog.Logger) (*Dashboard, error) {
	idx := NewIndex(storageDir)
	if err := idx.Load(); err != nil {
		logger.Warn("failed to load initial PBOMs", "error", err)
	}

	funcMap := template.FuncMap{
		"shortSHA":    shortSHA,
		"timeAgo":     timeAgo,
		"duration":    durationStr,
		"truncDigest": truncDigest,
		"dict":        dict,
	}

	// Parse separate template sets so each page's {{define "content"}} doesn't conflict
	sharedFiles := []string{
		"templates/layout.html",
		"templates/partials/pbom_table.html",
		"templates/partials/health_cards.html",
	}

	overviewTmpl, err := template.New("").Funcs(funcMap).ParseFS(embeddedFS,
		append(sharedFiles, "templates/overview.html")...)
	if err != nil {
		return nil, fmt.Errorf("parsing overview templates: %w", err)
	}

	detailTmpl, err := template.New("").Funcs(funcMap).ParseFS(embeddedFS,
		append(sharedFiles, "templates/detail.html")...)
	if err != nil {
		return nil, fmt.Errorf("parsing detail templates: %w", err)
	}

	// Partials-only template for htmx partial responses
	partialsTmpl, err := template.New("").Funcs(funcMap).ParseFS(embeddedFS,
		"templates/partials/pbom_table.html",
		"templates/partials/health_cards.html",
	)
	if err != nil {
		return nil, fmt.Errorf("parsing partial templates: %w", err)
	}

	staticFS, err := fs.Sub(embeddedFS, "static")
	if err != nil {
		return nil, fmt.Errorf("creating static FS: %w", err)
	}

	return &Dashboard{
		index:        idx,
		overviewTmpl: overviewTmpl,
		detailTmpl:   detailTmpl,
		partialsTmpl: partialsTmpl,
		staticFS:     staticFS,
		logger:       logger,
	}, nil
}

// RegisterRoutes adds dashboard routes to the given mux.
func (d *Dashboard) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /ui", d.handleOverview)
	mux.HandleFunc("GET /ui/", d.handleOverview)
	mux.HandleFunc("GET /ui/pbom/{owner}/{repo}/{runID}", d.handleDetail)
	mux.HandleFunc("GET /api/pboms", d.handleAPIList)
	mux.HandleFunc("GET /api/pboms/{owner}/{repo}/{runID}", d.handleAPIDetail)
	mux.Handle("GET /ui/static/", http.StripPrefix("/ui/static/", http.FileServer(http.FS(d.staticFS))))
	mux.HandleFunc("GET /ui/partials/table", d.handlePartialTable)
	mux.HandleFunc("GET /ui/partials/cards", d.handlePartialCards)
}

// Refresh reloads PBOMs from the storage directory.
func (d *Dashboard) Refresh() {
	if err := d.index.Load(); err != nil {
		d.logger.Error("dashboard refresh failed", "error", err)
	}
}

// Template helper functions

func shortSHA(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

func timeAgo(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		days := int(d.Hours() / 24)
		if days == 1 {
			return "1d ago"
		}
		return fmt.Sprintf("%dd ago", days)
	}
}

func durationStr(start, end *time.Time) string {
	if start == nil || end == nil {
		return "-"
	}
	d := end.Sub(*start)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
}

func truncDigest(d string) string {
	if len(d) > 19 {
		return d[:19] + "..."
	}
	return d
}

// dict creates a map from alternating key-value pairs (for passing data to sub-templates).
func dict(values ...any) map[string]any {
	m := make(map[string]any, len(values)/2)
	for i := 0; i+1 < len(values); i += 2 {
		key, ok := values[i].(string)
		if ok {
			m[key] = values[i+1]
		}
	}
	return m
}

// Page data types

type overviewData struct {
	Title       string
	Version     string
	PBOMCount   int
	Entries     []IndexEntry
	HealthCards []IndexEntry
	Filters     ListOptions
}

type detailData struct {
	Title     string
	Version   string
	PBOMCount int
	Owner     string
	Repo      string
	RunID     string
	PBOM      *schema.PBOM
}
