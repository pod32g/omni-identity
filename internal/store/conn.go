package store

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
)

// dialect identifies the active SQL backend.
type dialect int

const (
	dialectSQLite dialect = iota
	dialectPostgres
)

func (d dialect) String() string {
	if d == dialectPostgres {
		return "postgres"
	}
	return "sqlite"
}

// rebind rewrites `?` placeholders to the dialect's form. SQLite uses `?`
// natively (no-op); Postgres uses positional `$1, $2, …`. This is safe because
// the store's queries never contain a literal `?` inside string data.
func rebind(d dialect, query string) string {
	if d != dialectPostgres || !strings.Contains(query, "?") {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 8)
	n := 0
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(query[i])
	}
	return b.String()
}

// dbConn wraps *sql.DB so every query rebinds placeholders for the active
// dialect. It embeds *sql.DB, so non-overridden methods (Ping, Close,
// SetMaxOpenConns, …) pass through unchanged.
type dbConn struct {
	*sql.DB
	dialect dialect
}

func (c *dbConn) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return c.DB.ExecContext(ctx, rebind(c.dialect, query), args...)
}

func (c *dbConn) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return c.DB.QueryContext(ctx, rebind(c.dialect, query), args...)
}

func (c *dbConn) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return c.DB.QueryRowContext(ctx, rebind(c.dialect, query), args...)
}

// BeginTx returns a rebinding transaction handle.
func (c *dbConn) BeginTx(ctx context.Context, opts *sql.TxOptions) (*txConn, error) {
	tx, err := c.DB.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &txConn{Tx: tx, dialect: c.dialect}, nil
}

// txConn wraps *sql.Tx with the same rebinding behavior. Commit/Rollback pass
// through to the embedded *sql.Tx.
type txConn struct {
	*sql.Tx
	dialect dialect
}

func (t *txConn) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return t.Tx.ExecContext(ctx, rebind(t.dialect, query), args...)
}

func (t *txConn) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return t.Tx.QueryContext(ctx, rebind(t.dialect, query), args...)
}

func (t *txConn) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return t.Tx.QueryRowContext(ctx, rebind(t.dialect, query), args...)
}
