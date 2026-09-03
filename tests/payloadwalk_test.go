package tests

import "github.com/tinywasm/model"

// view (v0.2.0+) wraps every write in an UNEXPORTED args struct — save ships
// saveArgs{records:[...]}, delete ships deleteArgs{ids:[...]}, both plural
// (N=1 is a batch of one). A consumer/test cannot type-assert the payload, so
// it reads the encoding through model.FieldWriter. These helpers do exactly
// that for the two shapes the user-view tests check.

func savedRecords(args model.Encodable) []model.Encodable {
	w := &payloadWalk{}
	args.EncodeFields(w)
	return w.records
}

func deletedIDs(args model.Encodable) []string {
	w := &payloadWalk{}
	args.EncodeFields(w)
	return w.ids
}

type payloadWalk struct {
	records []model.Encodable
	ids     []string
}

func (*payloadWalk) String(string, string)          {}
func (*payloadWalk) Int(string, int64)              {}
func (*payloadWalk) Float(string, float64)          {}
func (*payloadWalk) Bool(string, bool)              {}
func (*payloadWalk) Bytes(string, []byte)           {}
func (*payloadWalk) Null(string)                    {}
func (*payloadWalk) Raw(string, string)             {}
func (*payloadWalk) Object(string, model.Encodable) {}
func (w *payloadWalk) Array(name string, _ int) model.ArrayWriter {
	switch name {
	case "records":
		return &recArr{w}
	case "ids":
		return (*idArr)(&w.ids)
	}
	return discardArr{}
}

type recArr struct{ w *payloadWalk }

func (recArr) String(string)              {}
func (recArr) Int(int64)                  {}
func (recArr) Float(float64)              {}
func (recArr) Bool(bool)                  {}
func (recArr) Bytes([]byte)               {}
func (a recArr) Object(v model.Encodable) { a.w.records = append(a.w.records, v) }
func (recArr) Close()                     {}

type idArr []string

func (a *idArr) String(v string)     { *a = append(*a, v) }
func (*idArr) Int(int64)             {}
func (*idArr) Float(float64)         {}
func (*idArr) Bool(bool)             {}
func (*idArr) Bytes([]byte)          {}
func (*idArr) Object(model.Encodable) {}
func (*idArr) Close()                {}

type discardArr struct{}

func (discardArr) String(string)          {}
func (discardArr) Int(int64)              {}
func (discardArr) Float(float64)          {}
func (discardArr) Bool(bool)              {}
func (discardArr) Bytes([]byte)           {}
func (discardArr) Object(model.Encodable) {}
func (discardArr) Close()                 {}
