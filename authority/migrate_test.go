package authority_test

import (
	"testing"

	"github.com/tinywasm/auth/authority"
	"github.com/tinywasm/ddl"
	"github.com/tinywasm/model"
)

type dummyExecer struct{}

func (d *dummyExecer) Exec(sql string, args ...any) error {
	return nil
}

type dummyCompiler struct{}

func (d *dummyCompiler) CompileDDL(stmt ddl.Stmt, m model.Model) (string, []any, error) {
	return "", nil, nil
}

func TestMigrateAcceptsExecer(t *testing.T) {
	var execer ddl.Execer = &dummyExecer{}
	var compiler ddl.Compiler = &dummyCompiler{}

	// Compile-time check / call test to verify Migrate accepts ddl.Execer
	_ = authority.Migrate(execer, compiler)
}
