package web

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/pod32g/omni-identity/internal/model"
)

// Enrollment notifications (best-effort, only when SMTP is configured): the
// owner learns about every new device on their account — the one signal that
// catches a socially engineered approval (threat model §4.3) — and admins
// learn when an enrollment is waiting for them. Failures are logged, never
// surfaced to the enrolling endpoint, and never block the request.

func (s *Server) notifyEnabled() bool { return s.mailer != nil && s.mailer.Enabled() }

// notifyDeviceEnrolled emails the owner (and, for pending devices, the admins).
func (s *Server) notifyDeviceEnrolled(dev *model.Device, owner *model.User) {
	if !s.notifyEnabled() {
		return
	}
	base := strings.TrimRight(s.settings.Current().PublicURL, "/")
	product := s.mfaIssuer()
	go func() {
		status := "It is active and can sign in as you."
		if dev.IsPending() {
			status = "It is waiting for an administrator to approve it and cannot sign in yet."
		}
		body := fmt.Sprintf("A device was enrolled to your %s account.\n\n"+
			"  Name:      %s\n  Hostname:  %s\n  Platform:  %s %s\n  Enrolled:  %s\n\n%s\n\n"+
			"If you did not do this, revoke it now:\n  %s/account/devices\n",
			product, dev.Name, dev.Hostname, dev.Platform, dev.Architecture,
			dev.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"), status, base)
		s.sendNotice(owner.Email, "New device enrolled: "+dev.Name, body)

		if dev.IsPending() {
			admins, _ := s.db.ListUsers(context.Background())
			for _, a := range admins {
				if !a.IsAdmin || a.Disabled || a.Email == "" || a.ID == owner.ID {
					continue
				}
				s.sendNotice(a.Email, "Device enrollment awaiting approval: "+dev.Name,
					fmt.Sprintf("%s enrolled the device %q (%s, %s) and it is waiting for approval.\n\n  %s/admin/devices/%s\n",
						owner.Username, dev.Name, dev.Hostname, dev.Platform, base, dev.ID))
			}
		}
	}()
}

// notifyDeviceApproved tells the owner their device may now sign in.
func (s *Server) notifyDeviceApproved(dev *model.Device) {
	if !s.notifyEnabled() {
		return
	}
	base := strings.TrimRight(s.settings.Current().PublicURL, "/")
	go func() {
		owner, err := s.db.GetUserByID(context.Background(), dev.OwnerUserID)
		if err != nil || owner.Email == "" {
			return
		}
		s.sendNotice(owner.Email, "Device approved: "+dev.Name,
			fmt.Sprintf("An administrator approved your device %q. It can now sign in as you.\n\n  %s/account/devices\n", dev.Name, base))
	}()
}

func (s *Server) sendNotice(to, subject, body string) {
	if to == "" {
		return
	}
	if err := s.mailer.Send(to, subject, body); err != nil {
		slog.Warn("device notification failed", "subject", subject, "error", err.Error())
	}
}
