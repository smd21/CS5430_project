package types

import (
	"time"
)

// stores the request and information needed for security protocol
// this is "m" on our protocol document
type Client_Message struct {
	Client      string    `json:"client"`
	Uid         string    `json:"uid"`
	Request     Request   `json:"request"`
	Tod         time.Time `json:"tod"`
	Sig_Pub_Key []byte    `json:"K_ds"`
}

type Signed_Client_Message struct {
	Msg Client_Message `json:"msg"`
	Sig []byte         `json:"sig"`
}

// Stores the client name and an encrypted signed message m. Possibly includes encrypted shared key
// A, {m, sig}K_shared and A, {m, sig}K_shared, {K_shared}K_S in our protocol
type Encrypted_Request struct {
	Client         string `json:"client"`
	Enc_Signed_M   []byte `json:"signed_message"`
	Enc_Shared_Key []byte `json:"enc_shared_key"`
}
