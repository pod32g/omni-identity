package enrollment

import (
	"strings"
	"testing"
)

func TestRenderQRShapesAndPolarity(t *testing.T) {
	url := "https://identity.example/device?user_code=BCDF-GHJK"
	dark, err := RenderQR(url, QRDark)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(dark, "\n"), "\n")
	if len(lines) < 15 || len(lines) > 30 {
		t.Errorf("unexpected height %d", len(lines))
	}
	for i, l := range lines {
		if strings.Count(l, "") != strings.Count(lines[0], "") {
			t.Errorf("line %d width differs", i)
		}
	}
	// The quiet zone is painted on a dark terminal (light border), blank on a light one.
	if !strings.HasPrefix(lines[0], "██") {
		t.Errorf("dark mode should paint the quiet zone: %q", lines[0])
	}
	light, _ := RenderQR(url, QRLight)
	if !strings.HasPrefix(light, "    ") {
		t.Errorf("light mode should leave the quiet zone blank")
	}
	if off, _ := RenderQR(url, QROff); off != "" {
		t.Error("off mode must render nothing")
	}
	if !qrForService("sshd") || qrForService("gdm-password") {
		t.Error("service gating wrong")
	}
}
