package migrations

import "embed"

// FS embeds all SQL migrations.
//
//go:embed *.sql
var FS embed.FS
