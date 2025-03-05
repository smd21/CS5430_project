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
var clientSigPrivKey *rsa.PrivateKey
var clientSigPubKey *rsa.PublicKey
var sessionKey []byte

func init() {
	name = uuid.NewString()
	Requests = make(chan NetworkData)
	Responses = make(chan NetworkData)
	uid = ""
	login_attempt = 0
	clientSigPrivKey = crypto_utils.NewPrivateKey()
	clientSigPubKey = &clientSigPrivKey.PublicKey
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
		client_msg := Client_Message{Client: name, Request: *request, Tod: crypto_utils.ReadClock(), Sig_Pub_Key: crypto_utils.PublicKeyToBytes(clientSigPubKey)}
		switch request.Op {
		case CREATE, DELETE, READ, WRITE, COPY:

			request.Uid = uid
			client_msg.Uid = uid
			enc_message := genEncryptedRequest(&client_msg, false)
			doOp(enc_message, server_resp)

		case LOGIN:
			uid = request.Uid
			sessionKey = crypto_utils.NewSessionKey()
			request.Uid = uid
			login_attempt++
			// hmm idk if this is right
			client_msg.Uid = uid

			enc_message := genEncryptedRequest(&client_msg, false)
			doOp(enc_message, server_resp)
		case LOGOUT:
			request.Uid = uid
			client_msg.Uid = uid
			enc_message := genEncryptedRequest(&client_msg, false)
			doOp(enc_message, server_resp)
			login_attempt = 0
			uid = ""
			sessionKey = nil
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
	case LOGIN:
		if login_attempt == 0 {
			return true
		}
	case LOGOUT:
		if login_attempt == 1 {
			return true
		}
	default:
		return false
	}
	return false
}

func genEncryptedRequest(request *Client_Message, is_login bool) *Encrypted_Request {
	var enc_req Encrypted_Request
	msg, _ := json.Marshal(request)
	sig := crypto_utils.Sign(msg, clientSigPrivKey)
	enc_m_sig := crypto_utils.EncryptSK(append(msg, sig...), sessionKey)
	if is_login {
		enc_key := crypto_utils.EncryptPK(sessionKey, serverPublicKey)
		enc_req = Encrypted_Request{Client: name, Enc_Signed_M: enc_m_sig, Enc_Shared_Key: enc_key}

	} else {
		enc_req = Encrypted_Request{Client: name, Enc_Signed_M: enc_m_sig}
	}
	return &enc_req
}

func doOp(request *Encrypted_Request, response *Server_Message) {
	requestBytes, _ := json.Marshal(request)
	json.Unmarshal(sendAndReceive(NetworkData{Payload: requestBytes, Name: name}).Payload, &response)

}

func sendAndReceive(toSend NetworkData) NetworkData {
	Requests <- toSend
	return <-Responses
}
