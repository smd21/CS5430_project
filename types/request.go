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
)

type Request struct {
	Key        string      `json:"key"`
	Val        interface{} `json:"val"`
	Op         Operation   `json:"op"`
	Source_Key string      `json:"src_key"`
	Dest_Key   string      `json:"dest_key"`
	Uid        string      `json:"uid"`
}
