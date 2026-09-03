# Installs the desktop launcher for `omni-enrollment` (default: the graphical
# enrollment page). Needs polkit (pkexec), present on every mainstream desktop.
#   sudo make install
PREFIX  ?= /usr
APPS     = $(DESTDIR)$(PREFIX)/share/applications
POLKIT   = $(DESTDIR)$(PREFIX)/share/polkit-1/actions
ICONS    = $(DESTDIR)$(PREFIX)/share/icons/hicolor/scalable/apps

install:
	install -D -m 0644 omni-enrollment.desktop $(APPS)/omni-enrollment.desktop
	install -D -m 0644 com.omni-identity.enrollment.policy $(POLKIT)/com.omni-identity.enrollment.policy
	install -D -m 0644 omni-enrollment.svg $(ICONS)/omni-enrollment.svg
	-update-desktop-database $(APPS) 2>/dev/null
	-gtk-update-icon-cache -q $(DESTDIR)$(PREFIX)/share/icons/hicolor 2>/dev/null

uninstall:
	rm -f $(APPS)/omni-enrollment.desktop $(POLKIT)/com.omni-identity.enrollment.policy $(ICONS)/omni-enrollment.svg

.PHONY: install uninstall
