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
	MODACL
	REVACL
)

type Request struct {
	Key        string      `json:"key"`
	Val        interface{} `json:"val"`
	Op         Operation   `json:"op"`
	Source_Key string      `json:"src_key"`
	Dest_Key   string      `json:"dst_key"`
	Uid        string      `json:"uid"`
	Pass       string      `json:"pass"`
	Old_pass   string      `json:"old_pass"`
	New_pass   string      `json:"new_pass"`
	Writers    []string    `json:"writers"`
	Readers    []string    `json:"readers"`
	Copyfroms  []string    `json:"copyfroms"`
	Copytos    []string    `json:"copytos"`
	Indirects  []string    `json:"indirects"`
}
