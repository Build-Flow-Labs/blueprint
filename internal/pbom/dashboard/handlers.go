package dashboard

import (
	"encoding/json"
	"net/http"

	"github.com/build-flow-labs/blueprint/pbom/schema"
)

func (d *Dashboard) handleOverview(w http.ResponseWriter, r *http.Request) {
	// Redirect /ui/ to /ui (avoid duplicate pages)
	if r.URL.Path == "/ui/" {
		http.Redirect(w, r, "/ui", http.StatusMovedPermanently)
		return
	}

	opts := parseListOptions(r)
	entries := d.index.List(opts)
	cards := d.index.LatestPerRepo()

	data := overviewData{
		Title:       "Overview",
		Version:     schema.Version,
		PBOMCount:   d.index.Count(),
		Entries:     entries,
		HealthCards: cards,
		Filters:     opts,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := d.overviewTmpl.ExecuteTemplate(w, "layout", data); err != nil {
		d.logger.Error("rendering overview", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func (d *Dashboard) handleDetail(w http.ResponseWriter, r *http.Request) {
	owner := r.PathValue("owner")
	repo := r.PathValue("repo")
	runID := r.PathValue("runID")

	pbom, err := d.index.Get(owner, repo, runID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	data := detailData{
		Title:     owner + "/" + repo + " #" + runID,
		Version:   schema.Version,
		PBOMCount: d.index.Count(),
		Owner:     owner,
		Repo:      repo,
		RunID:     runID,
		PBOM:      pbom,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := d.detailTmpl.ExecuteTemplate(w, "layout", data); err != nil {
		d.logger.Error("rendering detail", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func (d *Dashboard) handlePartialTable(w http.ResponseWriter, r *http.Request) {
	opts := parseListOptions(r)
	entries := d.index.List(opts)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := d.partialsTmpl.ExecuteTemplate(w, "pbom_table_content", entries); err != nil {
		d.logger.Error("rendering table partial", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func (d *Dashboard) handlePartialCards(w http.ResponseWriter, r *http.Request) {
	cards := d.index.LatestPerRepo()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := d.partialsTmpl.ExecuteTemplate(w, "health_cards_content", cards); err != nil {
		d.logger.Error("rendering cards partial", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func (d *Dashboard) handleAPIList(w http.ResponseWriter, r *http.Request) {
	opts := parseListOptions(r)
	entries := d.index.List(opts)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

func (d *Dashboard) handleAPIDetail(w http.ResponseWriter, r *http.Request) {
	owner := r.PathValue("owner")
	repo := r.PathValue("repo")
	runID := r.PathValue("runID")

	pbom, err := d.index.Get(owner, repo, runID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pbom)
}

func parseListOptions(r *http.Request) ListOptions {
	return ListOptions{
		Repo:      r.URL.Query().Get("repo"),
		Status:    r.URL.Query().Get("status"),
		Grade:     r.URL.Query().Get("grade"),
		SortField: r.URL.Query().Get("sort"),
		SortDesc:  r.URL.Query().Get("desc") == "true",
	}
}
