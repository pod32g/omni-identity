package store

import "errors"

// ErrNotFound is returned by repository getters when no row matches.
var ErrNotFound = errors.New("store: not found")

// scanner is satisfied by both *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}
