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
	ObtainServerPublicKey()
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

// probably need to adjust the type to use our custom wrappers
func ProcessOp(request *Request) *Response {
	server_resp := &Server_Message{S_Response: Response{Status: FAIL}}
	if validateRequest(request) {
		switch request.Op {
		case CREATE, DELETE, READ, WRITE, COPY:
			request.Uid = uid
			doOp(request, server_resp)
		case LOGIN:
			if login_attempt == 0 {
				uid = request.Uid
			}
			request.Uid = uid
			login_attempt++
			doOp(request, server_resp)
		case LOGOUT:
			request.Uid = uid
			login_attempt = 0
			uid = ""
			doOp(request, server_resp)
		default:
			// struct already default initialized to
			// FAIL status
		}
	}
	// i think this is correct
	return &server_resp.S_Response
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

func doOp(request *Request, response *Server_Message) {
	requestBytes, _ := json.Marshal(request)
	json.Unmarshal(sendAndReceive(NetworkData{Payload: requestBytes, Name: name}).Payload, &response)

	// here, we have to unpack the response and return it
}

func sendAndReceive(toSend NetworkData) NetworkData {
	Requests <- toSend
	return <-Responses
}
