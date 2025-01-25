package types

type Operation int
const (
	NOOP Operation = iota
	CREATE
	DELETE
	READ
	WRITE
)

type Request struct {
	Key  	string			`json:"key"`
	Val  	interface{} 	`json:"val"`
	Op   	Operation   	`json:"op"`
}
