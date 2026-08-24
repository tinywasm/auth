package authority

import (
	"github.com/tinywasm/ddl"
	"github.com/tinywasm/model"
	"github.com/tinywasm/orm"
	"github.com/tinywasm/auth"
)

func initSchema(db *orm.DB) error {
	models := []model.Model{
		&auth.User{}, &auth.Identity{}, &auth.LANIP{},
		&auth.OAuthState{}, &auth.Session{},
	}
	ddlCompiler, ok := db.RawConn().(ddl.Compiler)
	if !ok {
		return nil
	}
	sorted, err := ddl.TopologicalSort(models)
	if err != nil {
		return err
	}
	return ddl.New(db.RawConn(), ddlCompiler).Sync(sorted...)
}
