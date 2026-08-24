package auth

import (
	"github.com/tinywasm/input"
	"github.com/tinywasm/model"
)

var UserModel = model.Definition{
	Name: "user",
	Fields: model.Fields{
		{Name: "id", Type: model.Text(), DB: &model.FieldDB{PK: true}},
		{Name: "email", Type: input.Email(), DB: &model.FieldDB{Unique: true}},
		{Name: "name", Type: input.Text()},
		{Name: "phone", Type: input.Phone()},
		{Name: "status", Type: model.Text()},
		{Name: "avatar", Type: model.Text()},
		{Name: "created_at", Type: model.Int()},
	},
}

var SessionModel = model.Definition{
	Name: "session",
	Fields: model.Fields{
		{Name: "id", Type: model.Text(), DB: &model.FieldDB{PK: true}},
		{Name: "user_id", Type: model.Text(), DB: &model.FieldDB{RefColumn: "id"}, Ref: &UserModel},
		{Name: "expires_at", Type: model.Int()},
		{Name: "ip", Type: model.Text()},
		{Name: "user_agent", Type: model.Text()},
		{Name: "created_at", Type: model.Int()},
	},
}

var IdentityModel = model.Definition{
	Name: "identity",
	Fields: model.Fields{
		{Name: "id", Type: model.Text(), DB: &model.FieldDB{PK: true}},
		{Name: "user_id", Type: model.Text(), DB: &model.FieldDB{RefColumn: "id"}, Ref: &UserModel},
		{Name: "provider", Type: model.Text()},
		{Name: "provider_id", Type: model.Text()},
		{Name: "email", Type: model.Text()},
		{Name: "created_at", Type: model.Int()},
	},
}

var LANIPModel = model.Definition{
	Name: "lanip",
	Fields: model.Fields{
		{Name: "id", Type: model.Text(), DB: &model.FieldDB{PK: true}},
		{Name: "user_id", Type: model.Text(), DB: &model.FieldDB{RefColumn: "id"}, Ref: &UserModel},
		{Name: "ip", Type: model.Text()},
		{Name: "label", Type: model.Text()},
		{Name: "created_at", Type: model.Int()},
	},
}

var OAuthStateModel = model.Definition{
	Name: "oauth_state",
	Fields: model.Fields{
		{Name: "state", Type: model.Text(), DB: &model.FieldDB{PK: true}},
		{Name: "provider", Type: model.Text()},
		{Name: "expires_at", Type: model.Int()},
		{Name: "created_at", Type: model.Int()},
	},
}

var LoginDataModel = model.Definition{
	Name: "login_data",
	Fields: model.Fields{
		{Name: "email", Type: input.Email(), NotNull: true},
		{Name: "password", Type: input.Password(), NotNull: true},
	},
}

var RegisterDataModel = model.Definition{
	Name: "register_data",
	Fields: model.Fields{
		{Name: "name", Type: input.Text(), NotNull: true},
		{Name: "email", Type: input.Email(), NotNull: true},
		{Name: "password", Type: input.Password(), NotNull: true},
		{Name: "phone", Type: input.Phone()},
	},
}

var ProfileDataModel = model.Definition{
	Name: "profile_data",
	Fields: model.Fields{
		{Name: "name", Type: input.Text(), NotNull: true},
		{Name: "phone", Type: input.Phone()},
	},
}

var PasswordDataModel = model.Definition{
	Name: "password_data",
	Fields: model.Fields{
		{Name: "current", Type: input.Password(), NotNull: true},
		{Name: "new", Type: input.Password(), NotNull: true},
		{Name: "confirm", Type: input.Password(), NotNull: true},
	},
}
