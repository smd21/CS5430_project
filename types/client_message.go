package types

import (
	"time"
)

type Client_Message struct {
	Client     string    `json:"client"`
	Uid        string    `json:"uid"`
	C_Request  Request   `json:"c_request"`
	Tod        time.Time `json:"tod"`
	Shared_Key []byte    `json:"shared_key"`
}
