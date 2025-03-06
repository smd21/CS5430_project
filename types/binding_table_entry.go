package types

import (
	"time"
)

type Binding_Table_Entry struct {
	Uid        string    `json:"uid"`
	Tod        time.Time `json:"tod"`
	Shared_key []byte    `json:"K_ds"`
}
