package enrollment

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// LocalAccounts answers two questions about the machine's own account
// database (/etc/passwd, never NSS — asking NSS would find the identities
// this daemon itself serves): is a name a pre-existing local account that
// Omni must leave alone, and is a uid already taken.
type LocalAccounts interface {
	IsLocalAccount(name string) (bool, error)
	UIDInUse(uid int) (bool, error)
}

// PasswdFile reads /etc/passwd directly.
type PasswdFile struct {
	Path string // empty = /etc/passwd
}

func (p PasswdFile) path() string {
	if p.Path == "" {
		return "/etc/passwd"
	}
	return p.Path
}

func (p PasswdFile) each(fn func(name string, uid int) bool) error {
	f, err := os.Open(p.path())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) < 3 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		if !fn(fields[0], uid) {
			break
		}
	}
	return sc.Err()
}

func (p PasswdFile) IsLocalAccount(name string) (bool, error) {
	found := false
	err := p.each(func(n string, _ int) bool {
		if n == name {
			found = true
			return false
		}
		return true
	})
	return found, err
}

func (p PasswdFile) UIDInUse(uid int) (bool, error) {
	found := false
	err := p.each(func(_ string, u int) bool {
		if u == uid {
			found = true
			return false
		}
		return true
	})
	return found, err
}
