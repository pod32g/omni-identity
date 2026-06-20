package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/pod32g/omni-identity/internal/model"
)

// GetBranding returns the single branding row (id = 1). The row is seeded by
// migration 0003, so a missing row is treated as defaults.
func (d *DB) GetBranding(ctx context.Context) (*model.Branding, error) {
	row := d.sql.QueryRowContext(ctx, `
		SELECT product_name, logo_blob, logo_content_type, accent_color,
		       footer_text, background_style, updated_at
		FROM branding WHERE id = 1`)

	var (
		b    model.Branding
		logo []byte
	)
	err := row.Scan(&b.ProductName, &logo, &b.LogoContentType, &b.AccentColor,
		&b.FooterText, &b.BackgroundStyle, &b.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return &model.Branding{ProductName: "Omni Identity"}, nil
	}
	if err != nil {
		return nil, err
	}
	b.LogoBytes = logo
	return &b, nil
}

// UpdateBranding writes the text branding fields, leaving the logo untouched.
func (d *DB) UpdateBranding(ctx context.Context, b *model.Branding) error {
	_, err := d.sql.ExecContext(ctx, `
		UPDATE branding SET product_name = ?, accent_color = ?, footer_text = ?,
		       background_style = ?, updated_at = ?
		WHERE id = 1`,
		b.ProductName, b.AccentColor, b.FooterText, b.BackgroundStyle,
		time.Now().UTC())
	return err
}

// SetBrandingLogo stores (or clears, when bytes is nil) the uploaded logo.
func (d *DB) SetBrandingLogo(ctx context.Context, bytes []byte, contentType string) error {
	_, err := d.sql.ExecContext(ctx, `
		UPDATE branding SET logo_blob = ?, logo_content_type = ?, updated_at = ?
		WHERE id = 1`,
		bytes, contentType, time.Now().UTC())
	return err
}
