package types

import (
	"time"
)

type Hashed_Password struct {
	Password string `json:"pass"`
	Salt []byte `json:"salt"`
}

type Password_Table_Entry struct {
	Uid string `json:"uid"`
	Hashpass        []byte    `json:"hashed_password"`
}