// Package main is the entrypoint for fendix-app, the long-running
// HTTP server that GitHub posts webhooks to. It is a separate binary
// from fendix (the CLI scanner) because:
//
//   - Different deployment shape: long-running daemon vs one-shot CLI.
//   - Different operator concerns: secrets, TLS, container hosting.
//   - Users who only want the CLI shouldn't pay the binary-size cost
//     for the webhook server.
//
// Configuration is environment-variable based (12-factor):
//
//	FENDIX_APP_ID            Numeric App ID from the App's settings page.
//	FENDIX_APP_PRIVATE_KEY   PEM contents of the App's private key.
//	                         Either this OR FENDIX_APP_PRIVATE_KEY_FILE.
//	FENDIX_APP_PRIVATE_KEY_FILE  Path to the App's private-key PEM file.
//	FENDIX_WEBHOOK_SECRET    Webhook shared secret.
//	FENDIX_LISTEN_ADDR       HTTP listen address. Default: :8080.
//	FENDIX_GITHUB_API_URL    GitHub REST base URL. Default:
//	                         https://api.github.com (override for GHES).
//
// Setup walkthrough lives in docs/github-app.md.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/ghapp"
)

// Version is set at build time via ldflags (matches cmd/fendix).
var Version = "dev"

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfg, err := loadConfig()
	if err != nil {
		logger.Error("config load failed", "err", err)
		os.Exit(2)
	}

	creds, err := ghapp.LoadAppCredentials(cfg.AppID, cfg.PrivateKeyPEM)
	if err != nil {
		logger.Error("load app credentials failed", "err", err)
		os.Exit(2)
	}
	tokens := ghapp.NewTokenSource(creds, http.DefaultClient, cfg.GitHubAPIURL)

	handler := ghapp.NewHandler(tokens, cfg.GitHubAPIURL, http.DefaultClient)
	server := ghapp.NewServer(cfg.WebhookSecret, handler, logger)

	mux := http.NewServeMux()
	mux.Handle("/webhook", server)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, "fendix-app %s\n", Version)
	})

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("fendix-app listening",
			"addr", cfg.ListenAddr,
			"app_id", cfg.AppID,
			"version", Version,
		)
		errCh <- httpSrv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("listen failed", "err", err)
			os.Exit(1)
		}
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
		os.Exit(1)
	}
	logger.Info("shutdown complete")
}

type config struct {
	AppID          int64
	PrivateKeyPEM  []byte
	WebhookSecret  []byte
	ListenAddr     string
	GitHubAPIURL   string
}

func loadConfig() (*config, error) {
	appIDStr := os.Getenv("FENDIX_APP_ID")
	if appIDStr == "" {
		return nil, errors.New("FENDIX_APP_ID is required")
	}
	appID, err := strconv.ParseInt(appIDStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("FENDIX_APP_ID is not a valid integer: %w", err)
	}

	pemBytes, err := loadPrivateKey()
	if err != nil {
		return nil, err
	}

	secret := os.Getenv("FENDIX_WEBHOOK_SECRET")
	if secret == "" {
		return nil, errors.New("FENDIX_WEBHOOK_SECRET is required")
	}

	listenAddr := os.Getenv("FENDIX_LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":8080"
	}
	apiURL := os.Getenv("FENDIX_GITHUB_API_URL")
	if apiURL == "" {
		apiURL = "https://api.github.com"
	}

	return &config{
		AppID:         appID,
		PrivateKeyPEM: pemBytes,
		WebhookSecret: []byte(secret),
		ListenAddr:    listenAddr,
		GitHubAPIURL:  apiURL,
	}, nil
}

func loadPrivateKey() ([]byte, error) {
	if inline := os.Getenv("FENDIX_APP_PRIVATE_KEY"); inline != "" {
		return []byte(inline), nil
	}
	if path := os.Getenv("FENDIX_APP_PRIVATE_KEY_FILE"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read FENDIX_APP_PRIVATE_KEY_FILE: %w", err)
		}
		return b, nil
	}
	return nil, errors.New("either FENDIX_APP_PRIVATE_KEY or FENDIX_APP_PRIVATE_KEY_FILE is required")
}
