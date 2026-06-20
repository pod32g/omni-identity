package web

import (
	"context"
	"sync"

	"github.com/pod32g/omni-identity/internal/model"
)

// BrandingView is the read-only branding surface exposed to templates via the
// `brand` template function. It is safe to render on every page.
type BrandingView struct {
	ProductName     string
	AccentColor     string
	FooterText      string
	BackgroundStyle string
	HasLogo         bool
	LogoURL         string
}

// defaultBranding is used before the service loads or when the row is empty.
func defaultBranding() BrandingView {
	return BrandingView{ProductName: "Omni Identity"}
}

// brandingService loads and caches the single branding row, refreshing the cache
// when an admin saves changes.
type brandingService struct {
	db *brandingStore
	mu sync.RWMutex
	v  BrandingView
}

// brandingStore is the persistence surface the service needs (satisfied by *store.DB).
type brandingStore struct {
	get func(ctx context.Context) (*model.Branding, error)
}

func newBrandingService(get func(ctx context.Context) (*model.Branding, error)) *brandingService {
	s := &brandingService{db: &brandingStore{get: get}, v: defaultBranding()}
	s.Reload(context.Background())
	return s
}

// Reload refreshes the cached view from the store.
func (s *brandingService) Reload(ctx context.Context) {
	b, err := s.db.get(ctx)
	if err != nil || b == nil {
		return
	}
	view := BrandingView{
		ProductName:     b.ProductName,
		AccentColor:     b.AccentColor,
		FooterText:      b.FooterText,
		BackgroundStyle: b.BackgroundStyle,
		HasLogo:         len(b.LogoBytes) > 0,
		LogoURL:         "/branding/logo",
	}
	if view.ProductName == "" {
		view.ProductName = "Omni Identity"
	}
	s.mu.Lock()
	s.v = view
	s.mu.Unlock()
}

// Current returns the cached branding view.
func (s *brandingService) Current() BrandingView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v
}
