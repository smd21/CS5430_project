package types

import (
	"time"
)

type Server_Message struct {
	Client     string    `json:"client"`
	Uid        string    `json:"uid"`
	S_Response Response  `json:"s_response"`
	Tod        time.Time `json:"tod"`
}

type Encrypted_Response struct {
	Server       string `json:"server"`
	Enc_Signed_M []byte `json:"signed_message"`
}
