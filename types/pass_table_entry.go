package types

type Password_Table_Entry struct {
	Hashpass []byte `json:"hashed_password"`
	Salt     []byte `json:"salt"`
}
