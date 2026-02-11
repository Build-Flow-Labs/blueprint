// Package setup implements the interactive `pbom init` wizard for org onboarding.
package setup

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	gh "github.com/build-flow-labs/blueprint/internal/pbom/github"
)

// StepResult records the outcome of a single wizard step.
type StepResult struct {
	Step   string
	Action string // "created", "updated", "skipped", "dry-run", "error"
	Detail string
}

// Wizard orchestrates the interactive setup process.
type Wizard struct {
	ghClient *gh.Client
	prompt   *prompter
	out      io.Writer
	org      string
	dryRun   bool
	logger   *slog.Logger
	results  []StepResult
}

// NewWizard creates a setup wizard.
func NewWizard(token string, dryRun bool) *Wizard {
	return &Wizard{
		ghClient: gh.NewClient(token),
		prompt:   newPrompter(os.Stdin, os.Stdout),
		out:      os.Stdout,
		dryRun:   dryRun,
		logger:   slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})),
	}
}

// Run executes the full 7-step wizard.
func (w *Wizard) Run(ctx context.Context, org string) error {
	w.org = org

	fmt.Fprintln(w.out, "")
	fmt.Fprintln(w.out, "  PBOM Setup Wizard")
	fmt.Fprintln(w.out, "  =================")
	if w.dryRun {
		fmt.Fprintln(w.out, "  (dry-run mode: no changes will be made)")
	}
	fmt.Fprintln(w.out, "")

	steps := []struct {
		name string
		fn   func(context.Context) error
	}{
		{"Validate GitHub access", w.validateAccess},
		{"Create custom properties", w.createCustomProperties},
		{"Generate filter config", w.generateConfig},
		{"Push files to .github repo", w.pushToGitHubRepo},
		{"Create org webhook", w.createWebhook},
		{"Set repo properties", w.setRepoProperties},
	}

	for i, step := range steps {
		fmt.Fprintf(w.out, "\n--- Step %d/%d: %s ---\n", i+1, len(steps), step.name)
		if err := step.fn(ctx); err != nil {
			w.results = append(w.results, StepResult{
				Step:   step.name,
				Action: "error",
				Detail: err.Error(),
			})
			fmt.Fprintf(w.out, "  Error: %v\n", err)
			// Step 1 (validate) is fatal; others are recoverable
			if i == 0 {
				return fmt.Errorf("setup failed at step %d (%s): %w", i+1, step.name, err)
			}
			if !w.prompt.askYesNo("  Continue with remaining steps?", true) {
				return fmt.Errorf("setup aborted at step %d", i+1)
			}
		}
	}

	w.printSummary()
	return nil
}

// record adds a step result and prints it.
func (w *Wizard) record(step, action, detail string) {
	w.results = append(w.results, StepResult{Step: step, Action: action, Detail: detail})
	marker := "+"
	switch action {
	case "skipped":
		marker = "-"
	case "dry-run":
		marker = "~"
	case "error":
		marker = "!"
	}
	fmt.Fprintf(w.out, "  [%s] %s: %s\n", marker, action, detail)
}
