package enrollment

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// NSS identity socket (docs/LINUX-LOGIN-ARCHITECTURE.md §4, §6). libnss_omni
// asks the daemon to resolve names and ids; answers come from the user cache
// and, for a never-seen name while online, from one lookup at Omni. The
// socket is world-connectable (any process resolves names) and read-only:
// nothing it answers is secret and nothing it does changes state except
// caching an identity.

// NSSSocketName is the socket file under the runtime dir.
const NSSSocketName = "nss.sock"

const (
	nssNegativeTTL = time.Minute     // remember "no such user" briefly
	nssLookupLimit = 30              // online lookups per minute (enumeration brake)
	nssOnlineWait  = 4 * time.Second // bound on the online lookup (sshd is waiting)
	defaultShell   = "/bin/bash"
)

// identity is what NSS needs for a user.
type identity struct {
	Name  string
	UID   int
	GID   int
	Home  string
	Shell string
	Gecos string
}

func identityFromCache(uc *UserCache, shell string) identity {
	if shell == "" {
		shell = defaultShell
	}
	return identity{Name: uc.Username, UID: uc.UID, GID: uc.GID, Home: uc.Home, Shell: shell, Gecos: "Omni Identity " + uc.Sub}
}

// nssResolver serves identities with a small negative cache and an online
// lookup budget.
type nssResolver struct {
	a        *Agent
	accounts LocalAccounts
	pol      LoginPolicy
	logf     func(string, ...any)

	mu       sync.Mutex
	negative map[string]time.Time
	window   time.Time
	lookups  int
}

// ServeNSS listens on the identity socket until ctx is cancelled.
func (a *Agent) ServeNSS(ctx context.Context, accounts LocalAccounts, pol LoginPolicy, logf func(string, ...any)) error {
	if err := os.MkdirAll(a.RuntimeDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(a.RuntimeDir, NSSSocketName)
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o666); err != nil {
		l.Close()
		return err
	}
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	r := &nssResolver{a: a, accounts: accounts, pol: pol, logf: logf, negative: map[string]time.Time{}}
	logf("nss socket listening at %s", path)
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			continue
		}
		go r.handle(ctx, conn)
	}
}

func (r *nssResolver) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return
	}
	fields := strings.Fields(line)
	reply := "NONE"
	if len(fields) == 2 {
		switch fields[0] {
		case "PWNAM":
			if id, ok := r.byName(ctx, fields[1]); ok {
				reply = fmt.Sprintf("PW %s %d %d %s %s %s", id.Name, id.UID, id.GID, id.Home, id.Shell, id.Gecos)
			}
		case "PWUID":
			if id, ok := r.byUID(fields[1]); ok {
				reply = fmt.Sprintf("PW %s %d %d %s %s %s", id.Name, id.UID, id.GID, id.Home, id.Shell, id.Gecos)
			}
		case "GRNAM":
			if id, ok := r.byName(ctx, fields[1]); ok {
				reply = fmt.Sprintf("GR %s %d", id.Name, id.GID)
			}
		case "GRGID":
			if id, ok := r.byUID(fields[1]); ok {
				reply = fmt.Sprintf("GR %s %d", id.Name, id.GID)
			}
		}
	}
	_, _ = conn.Write([]byte(reply + "\n"))
}

// byName resolves from the cache, then (budgeted) from Omni.
func (r *nssResolver) byName(ctx context.Context, name string) (identity, bool) {
	name = strings.ToLower(name)
	if !validLinuxName.MatchString(name) {
		return identity{}, false
	}
	if uc, err := r.a.LoadUserCache(name); err == nil && uc != nil {
		return identityFromCache(uc, r.pol.LoginShell), true
	}
	// Never shadow a real local account.
	if local, _ := r.accounts.IsLocalAccount(name); local {
		return identity{}, false
	}
	r.mu.Lock()
	if until, ok := r.negative[name]; ok && time.Now().Before(until) {
		r.mu.Unlock()
		return identity{}, false
	}
	now := time.Now()
	if now.Sub(r.window) > time.Minute {
		r.window, r.lookups = now, 0
	}
	if r.lookups >= nssLookupLimit {
		r.mu.Unlock()
		return identity{}, false
	}
	r.lookups++
	r.mu.Unlock()

	uc, err := r.a.lookupIdentityOnline(ctx, name, r.accounts)
	if err != nil || uc == nil {
		r.mu.Lock()
		r.negative[name] = time.Now().Add(nssNegativeTTL)
		r.mu.Unlock()
		return identity{}, false
	}
	return identityFromCache(uc, r.pol.LoginShell), true
}

func (r *nssResolver) byUID(raw string) (identity, bool) {
	uid, err := strconv.Atoi(raw)
	if err != nil || uid < uidRangeStart || uid >= uidRangeStart+uidRangeSize+1000 {
		return identity{}, false
	}
	users, err := r.a.ListUserCaches()
	if err != nil {
		return identity{}, false
	}
	for _, uc := range users {
		if uc.UID == uid {
			return identityFromCache(uc, r.pol.LoginShell), true
		}
	}
	return identity{}, false
}

// lookupIdentityOnline asks Omni whether name is a user, derives the uid, and
// caches the identity (no secret, cannot log in offline until an online
// login). Returns nil, nil when Omni does not know the user.
func (a *Agent) lookupIdentityOnline(ctx context.Context, name string, accounts LocalAccounts) (*UserCache, error) {
	st, _, client, err := a.Open()
	if err != nil {
		return nil, err
	}
	lctx, cancel := context.WithTimeout(ctx, nssOnlineWait)
	defer cancel()
	tok, err := a.cachedDeviceToken(lctx, client, st.DeviceID)
	if err != nil {
		return nil, err
	}
	lu, err := client.LookupUser(lctx, tok, name)
	if err != nil {
		if IsOAuthError(err, "not_found") {
			return nil, nil
		}
		return nil, err
	}
	uid, err := allocateUID(lu.Sub, accounts, a)
	if err != nil {
		return nil, err
	}
	uc := &UserCache{Username: strings.ToLower(lu.Username), Sub: lu.Sub, UID: uid, GID: uid, Home: "/home/" + strings.ToLower(lu.Username), DeviceID: st.DeviceID}
	if err := a.SaveUserCache(uc); err != nil {
		return nil, err
	}
	if a.logf != nil {
		a.logf("nss: cached identity for %s (uid %d)", uc.Username, uid)
	}
	return uc, nil
}

// allocateUID derives the deterministic uid for sub and probes past any uid
// already used by /etc/passwd or another cached user.
func allocateUID(sub string, accounts LocalAccounts, a *Agent) (int, error) {
	cached, _ := a.ListUserCaches()
	taken := map[int]bool{}
	for _, uc := range cached {
		if uc.Sub != sub {
			taken[uc.UID] = true
		}
	}
	uid := uidFor(sub)
	for i := 0; i < 1000; i++ {
		inUse, err := accounts.UIDInUse(uid)
		if err != nil {
			return 0, err
		}
		if !inUse && !taken[uid] {
			return uid, nil
		}
		uid++
	}
	return 0, errors.New("no free uid in the Omni range")
}

// cachedDeviceToken returns a device token, reusing the last one while it
// has more than a minute left.
func (a *Agent) cachedDeviceToken(ctx context.Context, client *Client, deviceID string) (string, error) {
	a.tokMu.Lock()
	defer a.tokMu.Unlock()
	if a.tok != "" && time.Now().Before(a.tokExpires.Add(-time.Minute)) {
		return a.tok, nil
	}
	tok, err := client.DeviceToken(ctx, deviceID)
	if err != nil {
		return "", err
	}
	a.tok = tok.AccessToken
	a.tokExpires = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	return a.tok, nil
}
