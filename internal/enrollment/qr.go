package enrollment

import (
	"strings"

	qrcode "github.com/skip2/go-qrcode"
)

// QR polarity for terminal rendering. The verification URL is printed as a
// QR code so a user at a console or SSH prompt can scan it with a phone
// instead of transcribing the code (RFC 8628 §3.3.1 verification_uri_complete).
// It carries exactly what the printed URL carries, so it changes no trust
// assumption.
const (
	QROff   = "off"
	QRDark  = "dark"  // for dark terminal backgrounds (default)
	QRLight = "light" // for light terminal backgrounds
)

// RenderQR renders content as a compact half-block QR code, two modules per
// text line, including the standard 4-module quiet zone. mode is QRDark or
// QRLight; QROff returns "".
func RenderQR(content, mode string) (string, error) {
	if mode == QROff || mode == "" {
		return "", nil
	}
	q, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		return "", err
	}
	bits := q.Bitmap() // includes the quiet zone
	// On a dark terminal the "ink" is light, so a true-polarity code (dark
	// modules on a light background) is drawn by painting the LIGHT modules.
	paintDark := mode == QRLight
	dark := func(y, x int) bool {
		if y >= len(bits) {
			return false
		}
		return bits[y][x] == paintDark
	}
	var b strings.Builder
	for y := 0; y < len(bits); y += 2 {
		for x := 0; x < len(bits[y]); x++ {
			top, bottom := dark(y, x), dark(y+1, x)
			switch {
			case top && bottom:
				b.WriteRune('█')
			case top:
				b.WriteRune('▀')
			case bottom:
				b.WriteRune('▄')
			default:
				b.WriteRune(' ')
			}
		}
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// qrForService reports whether a login prompt for the given PAM service is
// shown on a text console where a QR code renders (sshd, login, pam-test).
// Graphical greeters draw prompts in proportional fonts, where it would be an
// unreadable blob, so they get the URL and code only.
func qrForService(service string) bool {
	switch service {
	case "sshd", "login", "pam-test", "su", "su-l":
		return true
	}
	return false
}
