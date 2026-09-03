# Builds libnss_omni.so.2 (glibc NSS module). Needs only gcc and libc headers.
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS ?= -shared -Wl,-z,relro,-z,now -Wl,-soname,libnss_omni.so.2
LIBDIR  ?= $(shell test -d /lib/x86_64-linux-gnu && echo /lib/x86_64-linux-gnu || \
            (test -d /lib/aarch64-linux-gnu && echo /lib/aarch64-linux-gnu || echo /lib64))

libnss_omni.so.2: nss_omni.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

install: libnss_omni.so.2
	install -m 0644 libnss_omni.so.2 $(LIBDIR)/libnss_omni.so.2
	ldconfig || true

clean:
	rm -f libnss_omni.so.2

.PHONY: install clean
