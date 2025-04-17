package types

type Code int

const (
	OK Code = iota
	FAIL
)

type Response struct {
	Status    Code        `json:"status"`
	Val       interface{} `json:"val"`
	Uid       string      `json:"uid"`
	Writers   []string    `json:"writers"`
	Readers   []string    `json:"readers"`
	Copyfroms []string    `json:"copyfroms"`
	Copytos   []string    `json:"copytos"`
	Indirects []string    `json:"indirects"`
	R_k       []string    `json:"r(k)"`
	W_k       []string    `json:"w(k)"`
	C_src_k   []string    `json:"c_src(k)"`
	C_dst_k   []string    `json:"c_dst(k)"`
}
