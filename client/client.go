package client

import (
	"crypto/rsa"
	"encoding/json"
	"os"

	"github.com/google/uuid"

	"crypto_utils"
	. "types"
)

var name string
var uid string
var login_attempt int
var Requests chan NetworkData
var Responses chan NetworkData

var serverPublicKey *rsa.PublicKey

func init() {
	name = uuid.NewString()
	Requests = make(chan NetworkData)
	Responses = make(chan NetworkData)
	uid = ""
	login_attempt = 0
}

func ObtainServerPublicKey() {
	serverPublicKeyBytes, err := os.ReadFile("SERVER_PUBLICKEY")
	if err != nil {
		panic(err)
	}
	serverPublicKey, err = crypto_utils.BytesToPublicKey(serverPublicKeyBytes)
	if err != nil {
		panic(err)
	}
}

func ProcessOp(request *Request) *Response {
	response := &Response{Status: FAIL}
	if validateRequest(request) {
		switch request.Op {
		case CREATE, DELETE, READ, WRITE, COPY:
			request.Uid = uid
			doOp(request, response)
		case LOGIN:
			if login_attempt == 0 {
				uid = request.Uid
			}
			request.Uid = uid
			login_attempt++
			doOp(request, response)
		case LOGOUT:
			request.Uid = uid
			login_attempt = 0
			uid = ""
			doOp(request, response)
		default:
			// struct already default initialized to
			// FAIL status
		}
	}
	return response
}

func validateRequest(r *Request) bool {
	switch r.Op {
	case CREATE, WRITE:
		return r.Key != "" && r.Val != nil
	case DELETE, READ:
		return r.Key != ""
	case COPY:
		return r.Dest_Key != "" && r.Source_Key != ""
	case LOGIN, LOGOUT:
		return true // always validate
	default:
		return false
	}
}

func doOp(request *Request, response *Response) {
	requestBytes, _ := json.Marshal(request)
	json.Unmarshal(sendAndReceive(NetworkData{Payload: requestBytes, Name: name}).Payload, &response)
}

func sendAndReceive(toSend NetworkData) NetworkData {
	Requests <- toSend
	return <-Responses
}
