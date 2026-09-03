# Builds pam_omni.so. Needs the PAM development headers:
#   Debian/Ubuntu: apt install libpam0g-dev gcc make
#   Fedora:        dnf install pam-devel gcc make
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS ?= -shared -Wl,-z,relro,-z,now
SECDIR  ?= $(shell test -d /lib/x86_64-linux-gnu/security && echo /lib/x86_64-linux-gnu/security || \
            (test -d /lib/aarch64-linux-gnu/security && echo /lib/aarch64-linux-gnu/security || echo /lib64/security))

pam_omni.so: pam_omni.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) -lpam

install: pam_omni.so
	install -m 0644 pam_omni.so $(SECDIR)/pam_omni.so

clean:
	rm -f pam_omni.so

.PHONY: install clean
