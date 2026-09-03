package enrollment

import (
	"os/user"
	"sort"
	"strings"
)

// When the agent runs as root through sudo or pkexec, the browser must be
// opened as the person sitting at the desktop, with that session's display
// variables: root has no Wayland/X session of its own and usually no browser
// profile. userSessionEnv rebuilds the minimum environment for xdg-open from
// what sudo/pkexec preserved plus the conventional per-user paths.
func userSessionEnv(u *user.User, base []string, exists func(string) bool) []string {
	get := func(k string) string {
		for _, kv := range base {
			if strings.HasPrefix(kv, k+"=") {
				return kv[len(k)+1:]
			}
		}
		return ""
	}
	rt := "/run/user/" + u.Uid
	env := map[string]string{
		"HOME":                     u.HomeDir,
		"USER":                     u.Username,
		"LOGNAME":                  u.Username,
		"PATH":                     orDefault(get("PATH"), "/usr/local/bin:/usr/bin:/bin"),
		"XDG_RUNTIME_DIR":          rt,
		"DBUS_SESSION_BUS_ADDRESS": orDefault(get("DBUS_SESSION_BUS_ADDRESS"), "unix:path="+rt+"/bus"),
		"DISPLAY":                  orDefault(get("DISPLAY"), ":0"),
	}
	for _, k := range []string{"LANG", "LC_ALL", "XDG_SESSION_TYPE", "XDG_CURRENT_DESKTOP", "BROWSER"} {
		if v := get(k); v != "" {
			env[k] = v
		}
	}
	switch v := get("WAYLAND_DISPLAY"); {
	case v != "":
		env["WAYLAND_DISPLAY"] = v
	case exists(rt + "/wayland-0"):
		env["WAYLAND_DISPLAY"] = "wayland-0"
	}
	switch v := get("XAUTHORITY"); {
	case v != "":
		env["XAUTHORITY"] = v
	case exists(u.HomeDir + "/.Xauthority"):
		env["XAUTHORITY"] = u.HomeDir + "/.Xauthority"
	case exists(rt + "/gdm/Xauthority"):
		env["XAUTHORITY"] = rt + "/gdm/Xauthority"
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+env[k])
	}
	return out
}
