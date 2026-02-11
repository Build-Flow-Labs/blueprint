package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/build-flow-labs/blueprint/internal/pbom/webhook"
	"github.com/spf13/cobra"
)

var (
	webhookAddr       string
	webhookSecret     string
	webhookToken      string
	webhookStorageDir string
)

var webhookCmd = &cobra.Command{
	Use:   "webhook",
	Short: "Start the PBOM webhook listener for GitHub org events",
	Long: `Starts an HTTP server that listens for workflow_run.completed webhook
events from GitHub. For each developer CI completion, it:

  1. Downloads the skeleton PBOM from the companion collector run
  2. Queries the GitHub API for runner details, secrets, and artifacts
  3. Enriches the PBOM with the collected data
  4. Stores the enriched PBOM locally

Configuration via flags or environment variables:
  --addr / PBOM_WEBHOOK_ADDR           Listen address (default :8080)
  --secret / PBOM_WEBHOOK_SECRET       GitHub webhook secret
  --token / GITHUB_TOKEN               GitHub token for API access
  --storage-dir / PBOM_STORAGE_DIR     Directory for enriched PBOMs`,
	RunE: runWebhook,
}

func init() {
	webhookCmd.Flags().StringVar(&webhookAddr, "addr", ":8080", "Listen address")
	webhookCmd.Flags().StringVar(&webhookSecret, "secret", "", "GitHub webhook secret (or PBOM_WEBHOOK_SECRET env)")
	webhookCmd.Flags().StringVar(&webhookToken, "token", "", "GitHub token (or GITHUB_TOKEN env)")
	webhookCmd.Flags().StringVar(&webhookStorageDir, "storage-dir", "./pbom-data", "Storage directory (or PBOM_STORAGE_DIR env)")
}

func runWebhook(cmd *cobra.Command, args []string) error {
	// Resolve config: flag > env > default
	if webhookSecret == "" {
		webhookSecret = os.Getenv("PBOM_WEBHOOK_SECRET")
	}
	if webhookToken == "" {
		webhookToken = os.Getenv("GITHUB_TOKEN")
	}
	if !cmd.Flags().Changed("storage-dir") {
		if dir := os.Getenv("PBOM_STORAGE_DIR"); dir != "" {
			webhookStorageDir = dir
		}
	}
	if !cmd.Flags().Changed("addr") {
		if addr := os.Getenv("PBOM_WEBHOOK_ADDR"); addr != "" {
			webhookAddr = addr
		}
	}

	if webhookSecret == "" {
		return fmt.Errorf("webhook secret required (--secret or PBOM_WEBHOOK_SECRET)")
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	cfg := webhook.Config{
		Addr:          webhookAddr,
		WebhookSecret: webhookSecret,
		GitHubToken:   webhookToken,
		StorageDir:    webhookStorageDir,
	}

	srv := webhook.NewServer(cfg, logger)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	return srv.Start(ctx)
}
