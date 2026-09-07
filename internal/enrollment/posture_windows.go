//go:build windows

package enrollment

import (
	"os/exec"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func collectPosture() Posture {
	p := Posture{OSName: "Windows"}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE); err == nil {
		if v, _, err := k.GetStringValue("ProductName"); err == nil && v != "" {
			p.OSName = v
		}
		if v, _, err := k.GetStringValue("DisplayVersion"); err == nil && v != "" {
			p.OSVersion = v
		}
		if b, _, err := k.GetStringValue("CurrentBuild"); err == nil && b != "" {
			p.OSVersion = strings.TrimSpace(p.OSVersion + " (build " + b + ")")
		}
		k.Close()
	}
	// Screen lock: the classic screen-saver policy keys, readable by the user.
	if k, err := registry.OpenKey(registry.CURRENT_USER, `Control Panel\Desktop`, registry.QUERY_VALUE); err == nil {
		active, _, e1 := k.GetStringValue("ScreenSaveActive")
		secure, _, e2 := k.GetStringValue("ScreenSaverIsSecure")
		if e1 == nil && e2 == nil {
			p.ScreenLock = boolPtr(active == "1" && secure == "1")
		}
		k.Close()
	}
	// BitLocker on the system drive. manage-bde needs elevation; the WMI
	// class is readable by standard users on most builds. Unknown on error.
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`(Get-CimInstance -Namespace root/cimv2/security/microsoftvolumeencryption -ClassName Win32_EncryptableVolume -Filter "DriveLetter='C:'" -ErrorAction Stop).ProtectionStatus`).Output()
	if err == nil {
		switch strings.TrimSpace(string(out)) {
		case "1":
			p.DiskEncrypted = boolPtr(true)
		case "0":
			p.DiskEncrypted = boolPtr(false)
		}
	}
	return p
}
