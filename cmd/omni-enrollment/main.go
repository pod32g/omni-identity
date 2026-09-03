// Command omni-enrollment is the endpoint agent that enrolls a machine with
// Omni Identity and keeps its device credential fresh.
//
// Usage:
//
//	omni-enrollment enroll     --issuer https://identity.example [--name NAME]
//	omni-enrollment status     [--json]
//	omni-enrollment renew                 # obtain a device token once
//	omni-enrollment rotate-key            # replace the device key
//	omni-enrollment unenroll              # revoke server-side and wipe local state
//	omni-enrollment daemon                # renewal loop (systemd service)
//	omni-enrollment version
//
// Flags may also come from OMNI_ENROLLMENT_* environment variables or from
// /etc/omni-enrollment/config.yaml (issuer, client_id, state_dir, runtime_dir,
// name, allow_insecure_http, ca_file). Precedence: flag > env > file.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pod32g/omni-identity/internal/enrollment"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

var version = "0.1.0-dev"

const defaultConfigPath = "/etc/omni-enrollment/config.yaml"

func main() {
	enrollment.Version = version
	// No command, or flags only (`omni-enrollment --issuer …`), opens the
	// graphical page: it is the default way to enroll and manage a device.
	// The subcommands remain for terminals, SSH sessions, and scripts.
	if len(os.Args) < 2 || strings.HasPrefix(os.Args[1], "-") && !isHelpOrVersion(os.Args[1]) {
		if err := runGUI(os.Args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, "omni-enrollment:", err)
			os.Exit(1)
		}
		return
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "enroll":
		err = runEnroll(args)
	case "status":
		err = runStatus(args)
	case "renew":
		err = runRenew(args)
	case "rotate-key":
		err = runRotate(args)
	case "unenroll":
		err = runUnenroll(args)
	case "daemon":
		err = runDaemon(args)
	case "pam-test":
		err = runPAMTest(args)
	case "token":
		err = runToken(args)
	case "gui":
		err = runGUI(args)
	case "version", "-v", "--version":
		fmt.Println("omni-enrollment", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "omni-enrollment:", err)
		os.Exit(1)
	}
}

func isHelpOrVersion(arg string) bool {
	switch arg {
	case "-h", "--help", "-v", "--version":
		return true
	}
	return false
}

func usage() {
	fmt.Fprint(os.Stderr, `omni-enrollment — enroll this machine with Omni Identity

Usage:
  omni-enrollment [--issuer URL] [gui flags]   Open the local enrollment page (default)
  omni-enrollment <command> [flags]

Commands:
  enroll      Generate a device key and enroll it under your Omni account
              (--browser: use this machine's browser instead of a code)
  status      Show enrollment and daemon status
  renew       Obtain a fresh device token once (checks the device is still trusted)
  rotate-key  Replace the device key (requires the current key)
  unenroll    Revoke this device server-side and remove local state
  daemon      Run the renewal loop + PAM socket (used by the systemd service)
  pam-test    Run the Linux login conversation for a user on this terminal
  token       Ask the local broker for an access token (--audience <client id>)
  gui         Open a local web page to enroll and manage this device
              (the default when no command is given)
  version     Print the version

Run "omni-enrollment <command> -h" for command-specific flags.
`)
}

// fileConfig mirrors /etc/omni-enrollment/config.yaml.
type fileConfig struct {
	Issuer            string   `yaml:"issuer"`
	ClientID          string   `yaml:"client_id"`
	StateDir          string   `yaml:"state_dir"`
	RuntimeDir        string   `yaml:"runtime_dir"`
	Name              string   `yaml:"name"`
	AllowInsecureHTTP bool     `yaml:"allow_insecure_http"`
	CAFile            string   `yaml:"ca_file"`
	OfflineValidity   string   `yaml:"offline_validity"`
	LoginShell        string   `yaml:"login_shell"`
	RefreshInterval   string   `yaml:"refresh_interval"`
	QR                string   `yaml:"qr"`
	BrokerAudiences   []string `yaml:"broker_audiences"`
	KeyBackend        string   `yaml:"key_backend"`
	TPMDevice         string   `yaml:"tpm_device"`
}

// commonFlags registers the shared flags and returns a resolver applying
// flag > env > file precedence.
func commonFlags(fs *flag.FlagSet) func() (enrollment.Config, error) {
	var cfg enrollment.Config
	configPath := fs.String("config", envOr("OMNI_ENROLLMENT_CONFIG", defaultConfigPath), "config file (optional)")
	fs.StringVar(&cfg.Issuer, "issuer", "", "Omni Identity issuer URL (OMNI_ENROLLMENT_ISSUER)")
	fs.StringVar(&cfg.ClientID, "client-id", "", "OAuth client id (default omni-enrollment)")
	fs.StringVar(&cfg.StateDir, "state-dir", "", "directory for the device key and enrollment record (default "+enrollment.DefaultStateDir+")")
	fs.StringVar(&cfg.RuntimeDir, "runtime-dir", "", "directory for status.json (default "+enrollment.DefaultRuntimeDir+")")
	fs.StringVar(&cfg.Name, "name", "", "device display name (default hostname)")
	fs.BoolVar(&cfg.AllowInsecureHTTP, "allow-insecure-http", false, "permit an http:// issuer (private-network testing only)")
	fs.StringVar(&cfg.CAFile, "ca-file", "", "PEM bundle for a private CA")
	offline := fs.String("offline-validity", "", "how long offline login stays valid after the last trust refresh (default 168h)")
	fs.StringVar(&cfg.LoginShell, "login-shell", "", "shell for provisioned accounts (default /bin/bash)")
	refresh := fs.String("refresh-interval", "", "cap on the daemon's renewal/trust-refresh interval (default: half the device token lifetime)")
	fs.StringVar(&cfg.KeyBackend, "key-backend", "", "where the device key lives: file (default) or tpm")
	fs.StringVar(&cfg.TPMDevice, "tpm-device", "", "TPM for --key-backend tpm: /dev/tpmrm0 (default) or tcp://host:port (software TPM)")
	noQR := fs.Bool("no-qr", false, "do not print a QR code under the sign-in link")
	qrLight := fs.Bool("qr-light", false, "render the QR code for a light terminal background")
	return func() (enrollment.Config, error) {
		var fc fileConfig
		if raw, err := os.ReadFile(*configPath); err == nil {
			if err := yaml.Unmarshal(raw, &fc); err != nil {
				return cfg, fmt.Errorf("parse %s: %w", *configPath, err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return cfg, err
		}
		pick := func(flagV, env, fileV, def string) string {
			if flagV != "" {
				return flagV
			}
			if v := os.Getenv(env); v != "" {
				return v
			}
			if fileV != "" {
				return fileV
			}
			return def
		}
		cfg.Issuer = pick(cfg.Issuer, "OMNI_ENROLLMENT_ISSUER", fc.Issuer, "")
		cfg.ClientID = pick(cfg.ClientID, "OMNI_ENROLLMENT_CLIENT_ID", fc.ClientID, enrollment.DefaultClientID)
		cfg.StateDir = pick(cfg.StateDir, "OMNI_ENROLLMENT_STATE_DIR", fc.StateDir, enrollment.DefaultStateDir)
		cfg.RuntimeDir = pick(cfg.RuntimeDir, "OMNI_ENROLLMENT_RUNTIME_DIR", fc.RuntimeDir, enrollment.DefaultRuntimeDir)
		cfg.Name = pick(cfg.Name, "OMNI_ENROLLMENT_NAME", fc.Name, "")
		cfg.CAFile = pick(cfg.CAFile, "OMNI_ENROLLMENT_CA_FILE", fc.CAFile, "")
		if !cfg.AllowInsecureHTTP {
			if v, _ := strconv.ParseBool(os.Getenv("OMNI_ENROLLMENT_ALLOW_INSECURE_HTTP")); v || fc.AllowInsecureHTTP {
				cfg.AllowInsecureHTTP = true
			}
		}
		cfg.LoginShell = pick(cfg.LoginShell, "OMNI_ENROLLMENT_LOGIN_SHELL", fc.LoginShell, "")
		cfg.KeyBackend = pick(cfg.KeyBackend, "OMNI_ENROLLMENT_KEY_BACKEND", fc.KeyBackend, enrollment.KeyBackendFile)
		cfg.TPMDevice = pick(cfg.TPMDevice, "OMNI_ENROLLMENT_TPM_DEVICE", fc.TPMDevice, "")
		if cfg.KeyBackend != enrollment.KeyBackendFile && cfg.KeyBackend != enrollment.KeyBackendTPM {
			return cfg, fmt.Errorf("key_backend must be file or tpm (got %q)", cfg.KeyBackend)
		}
		cfg.BrokerAudiences = fc.BrokerAudiences
		if v := os.Getenv("OMNI_ENROLLMENT_BROKER_AUDIENCES"); v != "" {
			cfg.BrokerAudiences = strings.Fields(strings.ReplaceAll(v, ",", " "))
		}
		flagQR := ""
		switch {
		case *noQR:
			flagQR = enrollment.QROff
		case *qrLight:
			flagQR = enrollment.QRLight
		}
		cfg.QR = pick(flagQR, "OMNI_ENROLLMENT_QR", fc.QR, enrollment.QRDark)
		switch cfg.QR {
		case enrollment.QROff, enrollment.QRDark, enrollment.QRLight:
		default:
			return cfg, fmt.Errorf("qr must be one of off, dark, light (got %q)", cfg.QR)
		}
		var derr error
		if v := pick(*offline, "OMNI_ENROLLMENT_OFFLINE_VALIDITY", fc.OfflineValidity, ""); v != "" {
			if cfg.OfflineValidity, derr = time.ParseDuration(v); derr != nil {
				return cfg, fmt.Errorf("offline_validity: %w", derr)
			}
		}
		if v := pick(*refresh, "OMNI_ENROLLMENT_REFRESH_INTERVAL", fc.RefreshInterval, ""); v != "" {
			if cfg.RefreshInterval, derr = time.ParseDuration(v); derr != nil {
				return cfg, fmt.Errorf("refresh_interval: %w", derr)
			}
		}
		return cfg, nil
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func agentFor(cfg enrollment.Config) *enrollment.Agent {
	return &enrollment.Agent{StateDir: cfg.StateDir, RuntimeDir: cfg.RuntimeDir, Out: os.Stdout,
		Accounts: enrollment.PasswdFile{}, Policy: cfg.Policy()}
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func runEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	resolve := commonFlags(fs)
	browser := fs.Bool("browser", false, "authorize through this machine's browser (RFC 8252 loopback redirect) instead of a code on another device")
	_ = fs.Parse(args)
	cfg, err := resolve()
	if err != nil {
		return err
	}
	if cfg.Issuer == "" {
		return errors.New("--issuer (or OMNI_ENROLLMENT_ISSUER) is required")
	}
	if *browser {
		cfg.Browser = true
		cfg.OpenURL = enrollment.OpenBrowser
	}
	ctx, stop := signalContext()
	defer stop()
	_, err = agentFor(cfg).Enroll(ctx, cfg)
	return err
}

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	resolve := commonFlags(fs)
	asJSON := fs.Bool("json", false, "machine-readable output")
	_ = fs.Parse(args)
	cfg, err := resolve()
	if err != nil {
		return err
	}
	st, err := enrollment.LoadState(cfg.StateDir)
	if err != nil {
		return err
	}
	rt, _ := enrollment.ReadStatus(cfg.RuntimeDir)
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"enrollment": st, "daemon": rt})
	}
	fmt.Print(enrollment.Describe(st, rt))
	return nil
}

func runRenew(args []string) error {
	fs := flag.NewFlagSet("renew", flag.ExitOnError)
	resolve := commonFlags(fs)
	_ = fs.Parse(args)
	cfg, err := resolve()
	if err != nil {
		return err
	}
	ctx, stop := signalContext()
	defer stop()
	st, tok, err := agentFor(cfg).Renew(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("device %s is %s (trust=%s); token valid for %ds\n", st.DeviceID, st.Status, tok.DeviceTrust, tok.ExpiresIn)
	return nil
}

func runRotate(args []string) error {
	fs := flag.NewFlagSet("rotate-key", flag.ExitOnError)
	resolve := commonFlags(fs)
	_ = fs.Parse(args)
	cfg, err := resolve()
	if err != nil {
		return err
	}
	ctx, stop := signalContext()
	defer stop()
	st, err := agentFor(cfg).RotateKey(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("device key rotated; new fingerprint %s\n", st.Fingerprint)
	return nil
}

func runUnenroll(args []string) error {
	fs := flag.NewFlagSet("unenroll", flag.ExitOnError)
	resolve := commonFlags(fs)
	_ = fs.Parse(args)
	cfg, err := resolve()
	if err != nil {
		return err
	}
	ctx, stop := signalContext()
	defer stop()
	if err := agentFor(cfg).Unenroll(ctx); err != nil {
		return err
	}
	fmt.Println("device unenrolled; local key and enrollment record removed")
	return nil
}

func runDaemon(args []string) error {
	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	resolve := commonFlags(fs)
	_ = fs.Parse(args)
	cfg, err := resolve()
	if err != nil {
		return err
	}
	ctx, stop := signalContext()
	defer stop()
	log.SetFlags(0)
	log.Printf("omni-enrollment daemon %s starting (state %s)", version, cfg.StateDir)
	return agentFor(cfg).RunDaemon(ctx, enrollment.DaemonOptions{
		Accounts: enrollment.PasswdFile{}, Policy: cfg.Policy(),
		RefreshEvery: cfg.RefreshInterval, ServePAM: true,
		Broker: enrollment.BrokerPolicy{Audiences: cfg.BrokerAudiences},
	}, log.Printf)
}

// runGUI serves the local enrollment page on loopback and opens it.
func runGUI(args []string) error {
	fs := flag.NewFlagSet("gui", flag.ExitOnError)
	resolve := commonFlags(fs)
	listen := fs.String("listen", "127.0.0.1:0", "loopback address to serve the page on")
	noOpen := fs.Bool("no-open", false, "print the URL instead of opening a browser")
	_ = fs.Parse(args)
	cfg, err := resolve()
	if err != nil {
		return err
	}
	ctx, stop := signalContext()
	defer stop()
	gui, err := enrollment.NewGUI(agentFor(cfg), cfg)
	if err != nil {
		return err
	}
	url, err := gui.Serve(ctx, *listen)
	if err != nil {
		return err
	}
	fmt.Printf("Omni Enrollment GUI: %s\n(press Ctrl-C to stop)\n", url)
	if !*noOpen {
		if err := enrollment.OpenBrowser(url); err != nil {
			fmt.Fprintln(os.Stderr, "could not open a browser:", err)
		}
	}
	<-ctx.Done()
	return nil
}

// runToken asks the daemon's broker for a token as the calling user and
// prints it (or JSON with --json) for scripts and local apps.
func runToken(args []string) error {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	resolve := commonFlags(fs)
	audience := fs.String("audience", "", "client id of the application the token is for (required)")
	scope := fs.String("scope", "", "requested scope (default: everything the login granted that the audience allows)")
	asJSON := fs.Bool("json", false, "print {access_token, expires_in} as JSON")
	_ = fs.Parse(args)
	cfg, err := resolve()
	if err != nil {
		return err
	}
	if *audience == "" {
		return errors.New("--audience is required")
	}
	tok, expires, err := enrollment.RequestBrokerToken(cfg.RuntimeDir, *audience, *scope)
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"access_token": tok, "expires_in": expires, "token_type": "Bearer"})
	}
	fmt.Println(tok)
	return nil
}

// runPAMTest drives the login conversation on the terminal without PAM, for
// debugging the integration.
func runPAMTest(args []string) error {
	fs := flag.NewFlagSet("pam-test", flag.ExitOnError)
	resolve := commonFlags(fs)
	_ = fs.Parse(args)
	cfg, err := resolve()
	if err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: omni-enrollment pam-test <username>")
	}
	ctx, stop := signalContext()
	defer stop()
	v := agentFor(cfg).Login(ctx, terminalConversation{}, enrollment.LoginContext{Username: fs.Arg(0), Service: "pam-test"},
		enrollment.PasswdFile{}, cfg.Policy())
	switch v {
	case enrollment.VerdictOK:
		fmt.Println("verdict: OK")
	case enrollment.VerdictIgnore:
		fmt.Println("verdict: IGNORE (not an Omni-managed user)")
		os.Exit(2)
	default:
		fmt.Println("verdict: FAIL")
		os.Exit(1)
	}
	return nil
}

// terminalConversation implements enrollment.Conversation on the controlling
// terminal.
type terminalConversation struct{}

func (terminalConversation) Info(text string)  { fmt.Println(text) }
func (terminalConversation) Error(text string) { fmt.Fprintln(os.Stderr, text) }
func (terminalConversation) Prompt(text string, echo bool) (string, error) {
	fmt.Print(text)
	if !echo && term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		return string(b), err
	}
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}
