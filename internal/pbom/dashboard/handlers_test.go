package dashboard

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func setupTestDashboard(t *testing.T) (*Dashboard, string) {
	t.Helper()
	dir := t.TempDir()
	now := time.Now().UTC()

	writePBOM(t, dir, "acme_api_100.pbom.json",
		samplePBOM("acme/api", "main", "success", "A", 95, now))
	writePBOM(t, dir, "acme_web_200.pbom.json",
		samplePBOM("acme/web", "develop", "failure", "C", 72, now.Add(-time.Hour)))

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	dash, err := New(dir, logger)
	if err != nil {
		t.Fatal(err)
	}
	return dash, dir
}

func TestHandleOverview(t *testing.T) {
	dash, _ := setupTestDashboard(t)
	mux := http.NewServeMux()
	dash.RegisterRoutes(mux)

	req := httptest.NewRequest("GET", "/ui", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Pipeline Health Overview") {
		t.Error("expected overview heading in response")
	}
	if !strings.Contains(body, "acme/api") {
		t.Error("expected acme/api in response")
	}
	if !strings.Contains(body, "acme/web") {
		t.Error("expected acme/web in response")
	}
}

func TestHandleDetail(t *testing.T) {
	dash, _ := setupTestDashboard(t)
	mux := http.NewServeMux()
	dash.RegisterRoutes(mux)

	req := httptest.NewRequest("GET", "/ui/pbom/acme/api/100", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "acme/api") {
		t.Error("expected acme/api in detail page")
	}
	if !strings.Contains(body, "abc1234") {
		t.Error("expected short SHA in detail page")
	}
}

func TestHandleDetailNotFound(t *testing.T) {
	dash, _ := setupTestDashboard(t)
	mux := http.NewServeMux()
	dash.RegisterRoutes(mux)

	req := httptest.NewRequest("GET", "/ui/pbom/acme/missing/999", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleAPIList(t *testing.T) {
	dash, _ := setupTestDashboard(t)
	mux := http.NewServeMux()
	dash.RegisterRoutes(mux)

	req := httptest.NewRequest("GET", "/api/pboms", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected JSON content type, got %s", ct)
	}

	var entries []IndexEntry
	if err := json.NewDecoder(w.Body).Decode(&entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
}

func TestHandleAPIListFiltered(t *testing.T) {
	dash, _ := setupTestDashboard(t)
	mux := http.NewServeMux()
	dash.RegisterRoutes(mux)

	req := httptest.NewRequest("GET", "/api/pboms?status=failure", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var entries []IndexEntry
	if err := json.NewDecoder(w.Body).Decode(&entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 failure entry, got %d", len(entries))
	}
}

func TestHandleAPIDetail(t *testing.T) {
	dash, _ := setupTestDashboard(t)
	mux := http.NewServeMux()
	dash.RegisterRoutes(mux)

	req := httptest.NewRequest("GET", "/api/pboms/acme/api/100", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var pbom map[string]any
	if err := json.NewDecoder(w.Body).Decode(&pbom); err != nil {
		t.Fatal(err)
	}
	source := pbom["source"].(map[string]any)
	if source["repository"] != "acme/api" {
		t.Errorf("expected acme/api, got %v", source["repository"])
	}
}

func TestHandlePartialTable(t *testing.T) {
	dash, _ := setupTestDashboard(t)
	mux := http.NewServeMux()
	dash.RegisterRoutes(mux)

	req := httptest.NewRequest("GET", "/ui/partials/table", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	// Should be partial HTML (table rows), not full page
	if strings.Contains(body, "<!DOCTYPE html>") {
		t.Error("partial should not contain full HTML document")
	}
	if !strings.Contains(body, "acme/api") {
		t.Error("partial should contain table data")
	}
}

func TestHandleStaticFiles(t *testing.T) {
	dash, _ := setupTestDashboard(t)
	mux := http.NewServeMux()
	dash.RegisterRoutes(mux)

	req := httptest.NewRequest("GET", "/ui/static/style.css", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "PBOM Dashboard") {
		t.Error("expected CSS content")
	}
}

func TestRefresh(t *testing.T) {
	dash, dir := setupTestDashboard(t)

	// Initially 2 PBOMs
	if dash.index.Count() != 2 {
		t.Fatalf("expected 2, got %d", dash.index.Count())
	}

	// Add a third PBOM
	writePBOM(t, dir, "acme_svc_300.pbom.json",
		samplePBOM("acme/svc", "main", "success", "B", 85, time.Now().UTC()))

	// Refresh
	dash.Refresh()

	if dash.index.Count() != 3 {
		t.Errorf("expected 3 after refresh, got %d", dash.index.Count())
	}
}
