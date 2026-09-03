package web

import (
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/model"
)

// deviceView is the template-facing shape of a device.
type deviceView struct {
	ID           string
	Name         string
	Hostname     string
	Platform     string
	Architecture string
	Fingerprint  string
	ShortFP      string
	Algorithm    string
	Status       string
	TrustLevel   string
	Owner        string
	OwnerID      string
	Enrolled     string
	LastSeen     string
	Revoked      string
	IsActive     bool
	IsRevoked    bool
	IsPending    bool
	OwnerOnly    bool
}

func viewDevice(d model.Device, owner string, now time.Time) deviceView {
	v := deviceView{
		ID: d.ID, Name: d.Name, Hostname: d.Hostname, Platform: d.Platform, Architecture: d.Architecture,
		Fingerprint: d.Fingerprint, ShortFP: truncate(d.Fingerprint, 12), Algorithm: d.PublicKeyAlgorithm,
		Status: d.Status, TrustLevel: d.TrustLevel, Owner: owner, OwnerID: d.OwnerUserID,
		IsActive: d.IsActive(), IsRevoked: d.Status == model.DeviceStatusRevoked, IsPending: d.IsPending(), OwnerOnly: d.OwnerOnly,
	}
	if !d.EnrolledAt.IsZero() {
		v.Enrolled = d.EnrolledAt.Local().Format("2006-01-02 15:04 MST")
	}
	if d.LastSeenAt.IsZero() {
		v.LastSeen = "never"
	} else {
		v.LastSeen = humanSince(now, d.LastSeenAt)
	}
	if !d.RevokedAt.IsZero() {
		v.Revoked = d.RevokedAt.Local().Format("2006-01-02 15:04 MST")
	}
	return v
}

// humanSince renders "2 minutes ago" style relative times.
func humanSince(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		n := int(d.Minutes())
		return fmt.Sprintf("%d minute%s ago", n, plural(n))
	case d < 24*time.Hour:
		n := int(d.Hours())
		return fmt.Sprintf("%d hour%s ago", n, plural(n))
	case d < 48*time.Hour:
		return "yesterday"
	default:
		n := int(d.Hours() / 24)
		return fmt.Sprintf("%d days ago", n)
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// --- self-service: /account/devices ---

type accountDevicesPage struct {
	CSRFToken string
	Me        *model.User
	Active    string
	Devices   []deviceView
	Error     string
	Saved     string
}

func (s *Server) renderAccountDevices(w http.ResponseWriter, r *http.Request, status int, errMsg, saved string) {
	user := currentUser(r)
	devs, _ := s.db.ListDevicesForUser(r.Context(), user.ID)
	now := time.Now()
	views := make([]deviceView, 0, len(devs))
	for _, d := range devs {
		views = append(views, viewDevice(d, user.Username, now))
	}
	s.tmpl.render(w, status, "account_devices", accountDevicesPage{
		CSRFToken: auth.CSRFToken(w, r, s.cookieSecure()),
		Me:        user,
		Active:    "account",
		Devices:   views,
		Error:     errMsg,
		Saved:     saved,
	})
}

func (s *Server) handleAccountDevices(w http.ResponseWriter, r *http.Request) {
	s.renderAccountDevices(w, r, http.StatusOK, "", "")
}

// handleAccountRevokeDevice lets a user revoke one of their own devices.
func (s *Server) handleAccountRevokeDevice(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	user := currentUser(r)
	dev, err := s.db.GetDevice(r.Context(), r.PathValue("id"))
	if err != nil || dev.OwnerUserID != user.ID {
		s.renderAccountDevices(w, r, http.StatusNotFound, "Device not found.", "")
		return
	}
	if err := s.db.RevokeDevice(r.Context(), dev.ID, time.Now().UTC()); err != nil {
		s.renderAccountDevices(w, r, http.StatusBadRequest, "That device is already revoked.", "")
		return
	}
	s.audit(r, evtDeviceRevoked, auditEntry{actorUserID: user.ID, username: user.Username, success: true,
		detail: "device=" + dev.ID + " by=owner"})
	s.renderAccountDevices(w, r, http.StatusOK, "", "Device revoked. It can no longer obtain credentials.")
}

// handleAccountDevicePolicy lets an owner toggle owner-only sign-in.
func (s *Server) handleAccountDevicePolicy(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	user := currentUser(r)
	id := r.PathValue("id")
	ownerOnly := r.PostFormValue("owner_only") == "on" || r.PostFormValue("owner_only") == "true"
	if err := s.db.SetDeviceOwnerOnly(r.Context(), id, user.ID, ownerOnly); err != nil {
		s.renderAccountDevices(w, r, http.StatusNotFound, "Device not found.", "")
		return
	}
	s.audit(r, evtDevicePolicyUpdated, auditEntry{actorUserID: user.ID, username: user.Username, success: true,
		detail: "device=" + id + " owner_only=" + boolStr(ownerOnly)})
	msg := "Anyone with an Omni account may now sign in on this device."
	if ownerOnly {
		msg = "Only you can sign in on this device now."
	}
	s.renderAccountDevices(w, r, http.StatusOK, "", msg)
}

// --- admin: /admin/devices ---

type adminDevicesPage struct {
	CSRFToken string
	Me        *model.User
	Active    string
	Devices   []deviceView
	Active_   int
	Error     string
	Saved     string
}

type adminDeviceDetailPage struct {
	CSRFToken string
	Me        *model.User
	Active    string
	Device    deviceView
	PublicKey string
	Error     string
}

// usernameIndex maps user ids to usernames for display.
func (s *Server) usernameIndex(r *http.Request) map[string]string {
	idx := map[string]string{}
	users, _ := s.db.ListUsers(r.Context())
	for _, u := range users {
		idx[u.ID] = u.Username
	}
	return idx
}

func (s *Server) renderAdminDevices(w http.ResponseWriter, r *http.Request, status int, errMsg, saved string) {
	devs, _ := s.db.ListDevices(r.Context())
	names := s.usernameIndex(r)
	now := time.Now()
	page := adminDevicesPage{
		CSRFToken: auth.CSRFToken(w, r, s.cookieSecure()),
		Me:        currentUser(r),
		Active:    "devices",
		Error:     errMsg,
		Saved:     saved,
	}
	for _, d := range devs {
		v := viewDevice(d, names[d.OwnerUserID], now)
		if v.IsActive {
			page.Active_++
		}
		page.Devices = append(page.Devices, v)
	}
	sort.SliceStable(page.Devices, func(i, j int) bool {
		// Active first, then newest.
		if page.Devices[i].IsActive != page.Devices[j].IsActive {
			return page.Devices[i].IsActive
		}
		return false
	})
	s.tmpl.render(w, status, "admin_devices", page)
}

func (s *Server) handleAdminDevices(w http.ResponseWriter, r *http.Request) {
	s.renderAdminDevices(w, r, http.StatusOK, "", "")
}

func (s *Server) handleAdminDeviceDetail(w http.ResponseWriter, r *http.Request) {
	dev, err := s.db.GetDevice(r.Context(), r.PathValue("id"))
	if err != nil {
		s.renderError(w, http.StatusNotFound, "Device not found.")
		return
	}
	s.renderAdminDeviceDetail(w, r, http.StatusOK, dev, "")
}

func (s *Server) renderAdminDeviceDetail(w http.ResponseWriter, r *http.Request, status int, dev *model.Device, errMsg string) {
	owner := ""
	if u, err := s.db.GetUserByID(r.Context(), dev.OwnerUserID); err == nil {
		owner = u.Username
	}
	s.tmpl.render(w, status, "admin_device_detail", adminDeviceDetailPage{
		CSRFToken: auth.CSRFToken(w, r, s.cookieSecure()),
		Me:        currentUser(r),
		Active:    "devices",
		Device:    viewDevice(*dev, owner, time.Now()),
		PublicKey: dev.PublicKey,
		Error:     errMsg,
	})
}

func (s *Server) handleAdminRevokeDevice(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	id := r.PathValue("id")
	dev, err := s.db.GetDevice(r.Context(), id)
	if err != nil {
		s.renderAdminDevices(w, r, http.StatusNotFound, "Device not found.", "")
		return
	}
	if err := s.db.RevokeDevice(r.Context(), id, time.Now().UTC()); err != nil {
		s.renderAdminDeviceDetail(w, r, http.StatusBadRequest, dev, "That device is already revoked.")
		return
	}
	s.audit(r, evtDeviceRevoked, auditEntry{actorUserID: actorID(r), success: true,
		detail: "device=" + id + " owner=" + dev.OwnerUserID + " by=admin"})
	if fromDetail(r) {
		http.Redirect(w, r, "/admin/devices/"+id, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/devices", http.StatusSeeOther)
}

// handleAdminApproveDevice activates a pending enrollment.
func (s *Server) handleAdminApproveDevice(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	id := r.PathValue("id")
	dev, err := s.db.GetDevice(r.Context(), id)
	if err != nil {
		s.renderAdminDevices(w, r, http.StatusNotFound, "Device not found.", "")
		return
	}
	if err := s.db.ApproveDevice(r.Context(), id, time.Now().UTC()); err != nil {
		s.renderAdminDeviceDetail(w, r, http.StatusBadRequest, dev, "That device is not pending approval.")
		return
	}
	s.audit(r, evtDeviceApproved, auditEntry{actorUserID: actorID(r), success: true,
		detail: "device=" + id + " owner=" + dev.OwnerUserID})
	s.notifyDeviceApproved(dev)
	if fromDetail(r) {
		http.Redirect(w, r, "/admin/devices/"+id, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/devices", http.StatusSeeOther)
}

// handleAdminDeleteDevice removes a revoked device row (housekeeping). Active
// devices must be revoked first.
func (s *Server) handleAdminDeleteDevice(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := s.db.DeleteDevice(r.Context(), id); err != nil {
		s.renderAdminDevices(w, r, http.StatusBadRequest, "Only revoked devices can be deleted. Revoke it first.", "")
		return
	}
	s.audit(r, evtDeviceDeleted, auditEntry{actorUserID: actorID(r), success: true, detail: "device=" + id})
	http.Redirect(w, r, "/admin/devices", http.StatusSeeOther)
}
