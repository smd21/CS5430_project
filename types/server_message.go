package types

import (
	"time"
)

type Server_Message struct {
	Server     string    `json:"server"`
	Uid        string    `json:"uid"`
	S_Response Response  `json:"s_response"`
	Tod        time.Time `json:"tod"`
}
