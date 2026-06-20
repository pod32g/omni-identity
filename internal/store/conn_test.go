package store

import "testing"

func TestRebindSQLiteIsNoop(t *testing.T) {
	q := `SELECT a FROM t WHERE b = ? AND c = ?`
	if got := rebind(dialectSQLite, q); got != q {
		t.Errorf("sqlite rebind changed query: %q", got)
	}
}

func TestRebindPostgresNumbersPlaceholders(t *testing.T) {
	cases := []struct{ in, want string }{
		{`SELECT a FROM t WHERE b = ?`, `SELECT a FROM t WHERE b = $1`},
		{`INSERT INTO t (a, b, c) VALUES (?, ?, ?)`, `INSERT INTO t (a, b, c) VALUES ($1, $2, $3)`},
		{`UPDATE t SET a = ?, b = ? WHERE id = ?`, `UPDATE t SET a = $1, b = $2 WHERE id = $3`},
		{`SELECT 1`, `SELECT 1`}, // no placeholders
	}
	for _, c := range cases {
		if got := rebind(dialectPostgres, c.in); got != c.want {
			t.Errorf("rebind(%q)\n  got  %q\n  want %q", c.in, got, c.want)
		}
	}
}

func TestDialectString(t *testing.T) {
	if dialectSQLite.String() != "sqlite" || dialectPostgres.String() != "postgres" {
		t.Errorf("dialect names: %q %q", dialectSQLite, dialectPostgres)
	}
}

func TestOpenWithUnknownDriver(t *testing.T) {
	if _, err := OpenWith("mysql", "x"); err == nil {
		t.Error("expected error for unknown driver")
	}
}
