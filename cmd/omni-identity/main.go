// Command omni-identity is the single-binary Omni Identity provider.
//
// Usage:
//
//	omni-identity serve       [flags]   # run the HTTP server + admin UI (default)
//	omni-identity backup       --db P --out F   # online DB snapshot (VACUUM INTO)
//	omni-identity integrity    --db P           # PRAGMA integrity_check
//	omni-identity healthcheck  --url U          # HTTP-probe a URL (2xx = healthy)
//	omni-identity version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/pod32g/omni-identity/internal/config"
	"github.com/pod32g/omni-identity/internal/logship"
	"github.com/pod32g/omni-identity/internal/store"
	"github.com/pod32g/omni-identity/internal/web"
)

// version is overridable at build time via -ldflags "-X main.version=...".
var version = "0.1.0-dev"

func main() {
	// Default to "serve" so bare/flag-only invocations keep working, while
	// allowing subcommands the deploy pipeline depends on.
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 {
		switch args[0] {
		case "-h", "--help":
			cmd, args = "help", args[1:]
		case "-v", "--version":
			cmd, args = "version", args[1:]
		default:
			if !strings.HasPrefix(args[0], "-") {
				cmd, args = args[0], args[1:]
			}
		}
	}

	var err error
	switch cmd {
	case "serve":
		err = runServe(args)
	case "backup":
		err = runBackup(args)
	case "integrity":
		err = runIntegrity(args)
	case "healthcheck":
		err = runHealthcheck(args)
	case "version", "-v", "--version":
		fmt.Println("omni-identity", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Fatalf("omni-identity: %v", err)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `omni-identity — self-hosted OpenID Connect provider

Commands:
  serve        Run the HTTP server and admin UI (default)
  backup       Write a consistent online DB snapshot (VACUUM INTO)
  integrity    Run PRAGMA integrity_check; exit non-zero if unsound
  healthcheck  HTTP-probe a URL; exit non-zero unless it returns 2xx
  version      Print the version

Run "omni-identity <command> -h" for command-specific flags.
`)
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "config.yaml", "path to YAML config file (optional; env vars also apply)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Expose the build version on /metrics (omni_identity_build_info).
	web.BuildVersion = version

	// Optionally ship structured logs to omnilog (in addition to stdout).
	if cfg.Logging.Enabled {
		shipper, lerr := logship.NewHandler(logship.Config{
			URL: cfg.Logging.URL, APIKey: cfg.Logging.APIKey, Service: cfg.Logging.Service,
		})
		if lerr != nil {
			return fmt.Errorf("init log shipper: %w", lerr)
		}
		stdout := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
		slog.SetDefault(slog.New(logship.Fanout(stdout, shipper)))
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = shipper.Close(ctx)
		}()
		slog.Info("log shipping enabled", "omnilog", cfg.Logging.URL, "service", cfg.Logging.Service)
	}

	db, err := store.OpenWith(cfg.Database.Driver, cfg.Database.DSN())
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer db.Close()

	srv, err := web.NewServer(cfg, db)
	if err != nil {
		return fmt.Errorf("init server: %w", err)
	}
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		log.Printf("omni-identity serving on %s (issuer %s)", addr, cfg.Security.Issuer)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("server: %w", err)
	case <-ctx.Done():
		log.Print("shutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutdownCtx)
	}
}

func runBackup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	db := fs.String("db", "omni-identity.db", "path to the SQLite database")
	out := fs.String("out", "", "destination snapshot path (must not already exist)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("backup: --out is required")
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		return fmt.Errorf("backup: create destination dir: %w", err)
	}
	s, err := store.Open(*db)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.BackupTo(context.Background(), *out); err != nil {
		return err
	}
	fmt.Printf("backup written to %s\n", *out)
	return nil
}

func runIntegrity(args []string) error {
	fs := flag.NewFlagSet("integrity", flag.ExitOnError)
	db := fs.String("db", "omni-identity.db", "path to the SQLite database")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := store.Open(*db)
	if err != nil {
		return err
	}
	defer s.Close()
	ok, problems, err := s.IntegrityCheck(context.Background())
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("integrity check FAILED: %s", strings.Join(problems, "; "))
	}
	fmt.Println("integrity check: ok")
	return nil
}

func runHealthcheck(args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ExitOnError)
	url := fs.String("url", "http://localhost:8080/healthz", "URL to probe")
	timeout := fs.Duration("timeout", 5*time.Second, "request timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: *timeout}).Get(*url)
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("healthcheck: %s returned %d", *url, resp.StatusCode)
	}
	return nil
}
