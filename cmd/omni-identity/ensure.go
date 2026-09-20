package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/pod32g/omni-identity/internal/config"
	"github.com/pod32g/omni-identity/internal/store"
	"github.com/pod32g/omni-identity/internal/web"
)

// `admin ensure` and `client ensure` let an installer provision an instance
// without driving the setup wizard and the admin forms over HTTP. They read the
// same configuration as `serve`, are safe to run while it is running and safe
// to repeat, and print one JSON object on stdout. Secrets are read from a file
// or stdin, never from the command line.

// maxSecretInput bounds what is read from a secret file or stdin.
const maxSecretInput = 4096

func runAdmin(args []string) error {
	return runEnsureGroup("admin", args, "Create the first/local administrator if it does not exist", runAdminEnsure)
}

func runClient(args []string) error {
	return runEnsureGroup("client", args, "Create an OAuth client, or bring the given fields in line", runClientEnsure)
}

func runEnsureGroup(group string, args []string, summary string, ensure func([]string, io.Reader, io.Writer) error) error {
	help := func(w io.Writer) {
		fmt.Fprintf(w, "Usage: omni-identity %s ensure [flags]\n\n  ensure   %s\n\nRun \"omni-identity %s ensure -h\" for the flags.\n", group, summary, group)
	}
	if len(args) == 0 {
		help(os.Stderr)
		os.Exit(2)
	}
	switch args[0] {
	case "ensure":
		return ensure(args[1:], os.Stdin, os.Stdout)
	case "-h", "--help", "help":
		help(os.Stdout)
		return nil
	}
	fmt.Fprintf(os.Stderr, "unknown %s command %q\n\n", group, args[0])
	help(os.Stderr)
	os.Exit(2)
	return nil
}

func runAdminEnsure(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("admin ensure", flag.ExitOnError)
	configPath := fs.String("config", "config.yaml", "path to YAML config file (optional; env vars also apply)")
	username := fs.String("username", "", "administrator username (required)")
	email := fs.String("email", "", "administrator email (required)")
	passwordFile := fs.String("password-file", "", "file holding the password; used only if the account is created")
	passwordStdin := fs.Bool("password-stdin", false, "read the password from stdin")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: omni-identity admin ensure --username U --email E (--password-file F | --password-stdin)

Creates a local administrator when no user has that username. An existing
account is never modified: its password and role stay as they are, and a
username that exists without administrator rights is an error.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("admin ensure: unexpected argument %q", fs.Arg(0))
	}
	password, err := readSecretInput("password", *passwordFile, *passwordStdin, stdin)
	if err != nil {
		return fmt.Errorf("admin ensure: %w", err)
	}

	cfg, db, err := openForEnsure(*configPath)
	if err != nil {
		return err
	}
	defer db.Close()
	res, err := web.EnsureAdmin(context.Background(), db, cfg, web.AdminSpec{Username: *username, Email: *email, Password: password})
	if err != nil {
		return fmt.Errorf("admin ensure: %w", err)
	}
	return json.NewEncoder(stdout).Encode(res)
}

func runClientEnsure(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("client ensure", flag.ExitOnError)
	configPath := fs.String("config", "config.yaml", "path to YAML config file (optional; env vars also apply)")
	id := fs.String("id", "", "client_id (required)")
	name := fs.String("name", "", "client name (required when creating)")
	clientType := fs.String("type", "", "confidential (default) or public; an existing client's type is not changed")
	scopes := fs.String("scopes", "", `space-separated scopes (default when creating: "openid profile email")`)
	displayName := fs.String("display-name", "", "name shown on the login and consent pages")
	logoURL := fs.String("logo-url", "", "logo shown on the login and consent pages")
	homepageURL := fs.String("homepage-url", "", "application homepage")
	skipConsent := fs.Bool("skip-consent", false, "first-party client: do not show a consent screen")
	secretFile := fs.String("secret-file", "", "file holding the client secret to set (at least 32 random characters)")
	secretStdin := fs.Bool("secret-stdin", false, "read the client secret from stdin")
	var redirects, postLogout stringList
	fs.Var(&redirects, "redirect-uri", "redirect URI; repeat for several (at least one when creating)")
	fs.Var(&postLogout, "post-logout-redirect-uri", `post-logout redirect URI; repeat for several, "" for none`)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: omni-identity client ensure --id ID [flags]

Creates the client if it does not exist; otherwise updates the fields whose
flags are given and leaves every other field as it is. The redirect URI policy
is the one configured in the admin settings. A disabled client stays disabled.

With --secret-file or --secret-stdin that value becomes the client secret.
Without either, a new confidential client gets a generated secret, printed once
in the result; an existing client's secret is left alone.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("client ensure: unexpected argument %q", fs.Arg(0))
	}
	secret, err := readSecretInput("secret", *secretFile, *secretStdin, stdin)
	if err != nil {
		return fmt.Errorf("client ensure: %w", err)
	}

	// Only flags that were actually given are part of the desired state.
	spec := web.ClientSpec{ClientID: strings.TrimSpace(*id), Secret: secret}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "name":
			spec.Name = name
		case "type":
			spec.Type = clientType
		case "scopes":
			spec.Scopes = append([]string{}, strings.Fields(*scopes)...)
		case "display-name":
			spec.DisplayName = displayName
		case "logo-url":
			spec.LogoURL = logoURL
		case "homepage-url":
			spec.HomepageURL = homepageURL
		case "skip-consent":
			spec.SkipConsent = skipConsent
		case "redirect-uri":
			spec.RedirectURIs = redirects.values()
		case "post-logout-redirect-uri":
			spec.PostLogoutRedirectURIs = postLogout.values()
		}
	})

	cfg, db, err := openForEnsure(*configPath)
	if err != nil {
		return err
	}
	defer db.Close()
	res, err := web.EnsureClient(context.Background(), db, cfg, spec)
	if err != nil {
		return fmt.Errorf("client ensure: %w", err)
	}
	return json.NewEncoder(stdout).Encode(res)
}

// openForEnsure loads the configuration and opens the database the way `serve`
// does, so the commands act on the instance `serve` runs.
func openForEnsure(configPath string) (*config.Config, *store.DB, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load config: %w", err)
	}
	db, err := store.OpenWith(cfg.Database.Driver, cfg.Database.DSN())
	if err != nil {
		return nil, nil, fmt.Errorf("open store: %w", err)
	}
	return cfg, db, nil
}

// readSecretInput returns the secret from the file or from stdin, without its
// trailing line ending, or "" when neither source was requested.
func readSecretInput(what, file string, fromStdin bool, stdin io.Reader) (string, error) {
	var raw []byte
	var err error
	switch {
	case file != "" && fromStdin:
		return "", fmt.Errorf("give the %s by file or by stdin, not both", what)
	case file != "":
		f, oerr := os.Open(file)
		if oerr != nil {
			return "", fmt.Errorf("read %s: %w", what, oerr)
		}
		defer f.Close()
		raw, err = io.ReadAll(io.LimitReader(f, maxSecretInput+1))
	case fromStdin:
		raw, err = io.ReadAll(io.LimitReader(stdin, maxSecretInput+1))
	default:
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read %s: %w", what, err)
	}
	if len(raw) > maxSecretInput {
		return "", fmt.Errorf("%s is longer than %d bytes", what, maxSecretInput)
	}
	value := strings.TrimRight(string(raw), "\r\n")
	if value == "" {
		return "", errors.New("the " + what + " is empty")
	}
	return value, nil
}

// stringList is a repeatable string flag. Empty values are dropped, so a single
// "" yields an empty, but specified, list.
type stringList struct{ items []string }

func (l *stringList) String() string { return strings.Join(l.items, " ") }

func (l *stringList) Set(v string) error {
	if v = strings.TrimSpace(v); v != "" {
		l.items = append(l.items, v)
	}
	return nil
}

func (l *stringList) values() []string { return append([]string{}, l.items...) }
