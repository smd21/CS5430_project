package types

type Operation int

const (
	NOOP Operation = iota
	CREATE
	DELETE
	READ
	WRITE
	COPY
	LOGIN
	LOGOUT
	REGISTER
	CHANGE_PASS
)

type Request struct {
	Key        string      `json:"key"`
	Val        interface{} `json:"val"`
	Op         Operation   `json:"op"`
	Source_Key string      `json:"src_key"`
	Dest_Key   string      `json:"dst_key"`
	Uid        string      `json:"uid"`
	pass	   string	   `json:"pass"`
	old_pass   string	   `json:"old_pass"`
	new_pass   string	   `json:"new_pass"`
}
