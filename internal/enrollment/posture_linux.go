//go:build linux

package enrollment

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

func collectPosture() Posture {
	var p Posture
	if f, err := os.Open("/etc/os-release"); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			k, v, ok := strings.Cut(sc.Text(), "=")
			if !ok {
				continue
			}
			v = strings.Trim(v, `"`)
			switch k {
			case "NAME":
				p.OSName = v
			case "VERSION_ID":
				p.OSVersion = v
			}
		}
	}
	// Disk encryption: any dm-crypt device present means the system uses
	// full-disk (or at least a) LUKS volume; absence means unknown rather
	// than "no", since some systems encrypt elsewhere.
	if matches, _ := filepath.Glob("/sys/block/dm-*/dm/uuid"); len(matches) > 0 {
		for _, m := range matches {
			if raw, err := os.ReadFile(m); err == nil && strings.HasPrefix(string(raw), "CRYPT-") {
				p.DiskEncrypted = boolPtr(true)
				break
			}
		}
	}
	return p
}
