package store

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// TableCount reports how many rows a single table contributed to a CopyData run.
type TableCount struct {
	Table      string
	SourceRows int
	DestRows   int
}

// CopyReport summarizes a CopyData run, one entry per copied table.
type CopyReport struct {
	Tables []TableCount
}

// CopyData copies every application table from src into dst, preserving all
// rows. It backs the `migrate-data` subcommand that moves a SQLite deployment
// onto Postgres: dst must be a Postgres store, whose schema is introspected to
// order the copy by foreign-key dependency and to coerce SQLite's integer
// booleans to BOOLEAN. src and dst must be at the same migration version.
//
// The copy runs in a single destination transaction: existing rows (including
// the migration-seeded single-row defaults for branding/settings) are deleted
// first, then every source row is inserted. On any error the transaction rolls
// back, leaving dst untouched.
func CopyData(ctx context.Context, src, dst *DB) (*CopyReport, error) {
	if dst.dialect != dialectPostgres {
		return nil, fmt.Errorf("migrate-data: destination must be postgres, got %s", dst.dialect)
	}
	sv, err := currentVersion(src.sql.DB)
	if err != nil {
		return nil, fmt.Errorf("migrate-data: source schema version: %w", err)
	}
	dv, err := currentVersion(dst.sql.DB)
	if err != nil {
		return nil, fmt.Errorf("migrate-data: destination schema version: %w", err)
	}
	if sv != dv {
		return nil, fmt.Errorf("migrate-data: schema version mismatch (source %d, destination %d); upgrade both to the same version first", sv, dv)
	}

	tables, err := orderedTables(ctx, dst)
	if err != nil {
		return nil, err
	}

	tx, err := dst.sql.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }() // no-op once committed

	// Clear existing rows child-first so foreign keys are never violated.
	for i := len(tables) - 1; i >= 0; i-- {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+quoteIdent(tables[i])); err != nil {
			return nil, fmt.Errorf("migrate-data: clear %s: %w", tables[i], err)
		}
	}

	report := &CopyReport{}
	for _, table := range tables {
		n, err := copyTable(ctx, src, tx, table)
		if err != nil {
			return nil, fmt.Errorf("migrate-data: copy %s: %w", table, err)
		}
		var dstRows int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+quoteIdent(table)).Scan(&dstRows); err != nil {
			return nil, fmt.Errorf("migrate-data: count %s: %w", table, err)
		}
		report.Tables = append(report.Tables, TableCount{Table: table, SourceRows: n, DestRows: dstRows})
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("migrate-data: commit: %w", err)
	}
	return report, nil
}

// copyTable streams every row of table from src into the dst transaction,
// coercing SQLite integer booleans to the destination's BOOLEAN columns. It
// returns the number of rows read from the source.
func copyTable(ctx context.Context, src *DB, tx *txConn, table string) (int, error) {
	cols, types, err := destColumns(ctx, tx, table)
	if err != nil {
		return 0, err
	}
	if len(cols) == 0 {
		return 0, fmt.Errorf("no columns found")
	}

	quoted := make([]string, len(cols))
	for i, c := range cols {
		quoted[i] = quoteIdent(c)
	}
	selectSQL := "SELECT " + strings.Join(quoted, ", ") + " FROM " + quoteIdent(table)
	insertSQL := "INSERT INTO " + quoteIdent(table) + " (" + strings.Join(quoted, ", ") +
		") VALUES (" + strings.Repeat("?, ", len(cols)-1) + "?)"

	// Read straight from the source's *sql.DB: it is SQLite, so `?` placeholders
	// need no rebinding, and we never bind user input here (identifiers only).
	rows, err := src.sql.DB.QueryContext(ctx, selectSQL)
	if err != nil {
		return 0, fmt.Errorf("read source: %w", err)
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return 0, fmt.Errorf("scan source row: %w", err)
		}
		for i := range vals {
			if types[i] == "boolean" {
				vals[i] = toBool(vals[i])
			}
		}
		if _, err := tx.ExecContext(ctx, insertSQL, vals...); err != nil {
			return 0, fmt.Errorf("insert row %d: %w", n+1, err)
		}
		n++
	}
	return n, rows.Err()
}

// toBool maps a SQLite boolean (stored as INTEGER 0/1) to a Go bool that pgx can
// bind to a Postgres BOOLEAN column.
func toBool(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case bool:
		return x
	case int64:
		return x != 0
	case float64:
		return x != 0
	case []byte:
		return (len(x) == 1 && x[0] == '1') || strings.EqualFold(string(x), "true")
	case string:
		return x == "1" || strings.EqualFold(x, "true")
	default:
		return v
	}
}

// orderedTables returns the destination's application tables ordered so that a
// table always follows every table it references via a foreign key (parents
// before children). schema_migrations is excluded.
func orderedTables(ctx context.Context, dst *DB) ([]string, error) {
	tables, err := listTables(ctx, dst)
	if err != nil {
		return nil, err
	}
	parents, err := foreignKeyParents(ctx, dst)
	if err != nil {
		return nil, err
	}
	return topoSort(tables, parents)
}

func listTables(ctx context.Context, dst *DB) ([]string, error) {
	rows, err := dst.sql.QueryContext(ctx, `
		SELECT table_name FROM information_schema.tables
		WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
		  AND table_name <> 'schema_migrations'`)
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// foreignKeyParents maps each table to the set of distinct tables it references.
// Self-references are ignored — they do not constrain table-level ordering.
func foreignKeyParents(ctx context.Context, dst *DB) (map[string]map[string]bool, error) {
	rows, err := dst.sql.QueryContext(ctx, `
		SELECT tc.table_name AS child, ccu.table_name AS parent
		FROM information_schema.table_constraints tc
		JOIN information_schema.key_column_usage kcu
		  ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema
		JOIN information_schema.constraint_column_usage ccu
		  ON tc.constraint_name = ccu.constraint_name AND tc.table_schema = ccu.table_schema
		WHERE tc.constraint_type = 'FOREIGN KEY' AND tc.table_schema = 'public'`)
	if err != nil {
		return nil, fmt.Errorf("read foreign keys: %w", err)
	}
	defer rows.Close()
	parents := map[string]map[string]bool{}
	for rows.Next() {
		var child, parent string
		if err := rows.Scan(&child, &parent); err != nil {
			return nil, err
		}
		if child == parent {
			continue
		}
		if parents[child] == nil {
			parents[child] = map[string]bool{}
		}
		parents[child][parent] = true
	}
	return parents, rows.Err()
}

// topoSort orders tables parents-before-children using Kahn's algorithm,
// breaking ties alphabetically for deterministic output. It errors on a cycle.
func topoSort(tables []string, parents map[string]map[string]bool) ([]string, error) {
	known := map[string]bool{}
	for _, t := range tables {
		known[t] = true
	}
	indeg := map[string]int{}
	children := map[string][]string{}
	for _, t := range tables {
		for p := range parents[t] {
			if !known[p] {
				continue
			}
			indeg[t]++
			children[p] = append(children[p], t)
		}
	}
	var queue []string
	for _, t := range tables {
		if indeg[t] == 0 {
			queue = append(queue, t)
		}
	}
	sort.Strings(queue)

	var order []string
	for len(queue) > 0 {
		t := queue[0]
		queue = queue[1:]
		order = append(order, t)
		next := children[t]
		sort.Strings(next)
		for _, c := range next {
			indeg[c]--
			if indeg[c] == 0 {
				queue = append(queue, c)
			}
		}
		sort.Strings(queue)
	}
	if len(order) != len(tables) {
		return nil, fmt.Errorf("foreign-key cycle detected among tables")
	}
	return order, nil
}

// destColumns returns the destination column names and their information_schema
// data types in declaration order.
func destColumns(ctx context.Context, tx *txConn, table string) (cols, types []string, err error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT column_name, data_type FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = ?
		ORDER BY ordinal_position`, table)
	if err != nil {
		return nil, nil, fmt.Errorf("read columns: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, typ string
		if err := rows.Scan(&name, &typ); err != nil {
			return nil, nil, err
		}
		cols = append(cols, name)
		types = append(types, typ)
	}
	return cols, types, rows.Err()
}

// quoteIdent double-quotes a SQL identifier (table or column name) for both
// SQLite and Postgres. Identifiers here come from schema introspection, never
// user input, but quoting keeps the generated SQL unambiguous.
func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}
