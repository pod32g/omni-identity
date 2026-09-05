//go:build windows

package enrollment

import (
	"bytes"
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// On Windows the key file is wrapped with DPAPI (CryptProtectData, user
// scope): only the same Windows user on the same machine can unwrap it, so a
// copied file is useless. Unix file modes mean nothing on NTFS, hence no
// mode check; the profile directory's ACL is the guard.

var dpapiMagic = []byte("OMNI-DPAPI-1\n")

func protectKeyFile(pemBytes []byte) ([]byte, error) {
	in := windows.DataBlob{Size: uint32(len(pemBytes)), Data: &pemBytes[0]}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, windows.StringToUTF16Ptr("omni-enrollment device key"), nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	enc := unsafe.Slice(out.Data, out.Size)
	return append(append([]byte{}, dpapiMagic...), enc...), nil
}

func unprotectKeyFile(raw []byte) ([]byte, error) {
	if !bytes.HasPrefix(raw, dpapiMagic) {
		return raw, nil // a plain PEM (copied from elsewhere) still loads
	}
	enc := raw[len(dpapiMagic):]
	if len(enc) == 0 {
		return nil, errors.New("empty DPAPI blob")
	}
	in := windows.DataBlob{Size: uint32(len(enc)), Data: &enc[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte{}, unsafe.Slice(out.Data, out.Size)...), nil
}

func checkKeyFileMode(string) error { return nil }
