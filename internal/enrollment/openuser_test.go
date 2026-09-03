package enrollment

import (
	"os/user"
	"strings"
	"testing"
)

func TestUserSessionEnvRebuildsTheDesktopSession(t *testing.T) {
	u := &user.User{Uid: "1000", Gid: "1000", Username: "alice", HomeDir: "/home/alice"}
	exists := func(p string) bool { return p == "/run/user/1000/wayland-0" || p == "/home/alice/.Xauthority" }

	// sudo kept DISPLAY only: the rest comes from convention.
	env := strings.Join(userSessionEnv(u, []string{"DISPLAY=:1", "PATH=/usr/bin", "SUDO_USER=alice", "HOME=/root", "XDG_RUNTIME_DIR=/run/user/0"}, exists), "\n")
	for _, want := range []string{"HOME=/home/alice", "USER=alice", "LOGNAME=alice", "DISPLAY=:1", "PATH=/usr/bin",
		"XDG_RUNTIME_DIR=/run/user/1000", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus", "WAYLAND_DISPLAY=wayland-0", "XAUTHORITY=/home/alice/.Xauthority"} {
		if !strings.Contains(env, want+"\n") && !strings.HasSuffix(env, want) {
			t.Errorf("missing %q in\n%s", want, env)
		}
	}
	for _, leak := range []string{"SUDO_USER", "HOME=/root", "XDG_RUNTIME_DIR=/run/user/0"} {
		if strings.Contains(env, leak) {
			t.Errorf("root's %q leaked into the user's environment", leak)
		}
	}

	// pkexec clears everything: defaults still point at a usable session.
	env = strings.Join(userSessionEnv(u, nil, func(string) bool { return false }), "\n")
	for _, want := range []string{"DISPLAY=:0", "PATH=/usr/local/bin:/usr/bin:/bin", "XDG_RUNTIME_DIR=/run/user/1000"} {
		if !strings.Contains(env, want) {
			t.Errorf("missing default %q in\n%s", want, env)
		}
	}
	if strings.Contains(env, "XAUTHORITY") || strings.Contains(env, "WAYLAND_DISPLAY") {
		t.Errorf("invented session files:\n%s", env)
	}
}
