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
	var encrypted_resp Encrypted_Response
	if validateRequest(request) {
		client_msg := Client_Message{Client: name, Request: *request, Tod: crypto_utils.ReadClock(), Sig_Pub_Key: crypto_utils.PublicKeyToBytes(clientSigPubKey)}
		switch request.Op {
		case REGISTER:
			client_msg.One_Time_Key = crypto_utils.NewSessionKey() // generate a one time key
			enc_message := genEncryptedRequest(&client_msg, false, true)
			doOp(enc_message, &encrypted_resp)
		case CREATE, DELETE, READ, WRITE, COPY, CHANGE_PASS:
			client_msg.Request.Uid = uid
			client_msg.Uid = uid
			enc_message := genEncryptedRequest(&client_msg, false, false)
			doOp(enc_message, &encrypted_resp)
		case LOGIN:
			uid = request.Uid
			sessionKey = crypto_utils.NewSessionKey()
			client_msg.Request.Uid = uid
			login_attempt++
			client_msg.Uid = uid
			enc_message := genEncryptedRequest(&client_msg, true, false)
			doOp(enc_message, &encrypted_resp)
		case LOGOUT:
			client_msg.Request.Uid = uid
			client_msg.Uid = uid
			enc_message := genEncryptedRequest(&client_msg, false, false)
			doOp(enc_message, &encrypted_resp)
			// authenticate, then delete session key
			if !validateResponse(&client_msg, &encrypted_resp) {
				return &server_resp.S_Response
			}
			server_resp = decryptServer(&encrypted_resp)
			login_attempt = 0
			uid = ""
			sessionKey = nil
			return &server_resp.S_Response
		default:
			// struct already default initialized to
			// FAIL status
			server_resp.S_Response.Uid = uid
			return &server_resp.S_Response
		}
		if !validateResponse(&client_msg, &encrypted_resp) {
			// if we cannot authenticate then return a FAIL
			return &server_resp.S_Response
		}
		server_resp = decryptServer(&encrypted_resp)
	}
	// i think this is correct

	return &server_resp.S_Response
}

func decryptServer(encrypted *Encrypted_Response) *Server_Message {
	decrypted_bytes, _ := crypto_utils.DecryptSK(encrypted.Enc_Signed_M, sessionKey)
	var signed_server_resp Signed_Server_Message
	json.Unmarshal(decrypted_bytes, &signed_server_resp)
	return &signed_server_resp.Msg
}

func validateResponse(original_msg *Client_Message, response *Encrypted_Response) bool {
	decrypted_bytes, err := crypto_utils.DecryptSK(response.Enc_Signed_M, sessionKey)
	if err != nil {
		return false
	}

	var server_resp Signed_Server_Message
	json.Unmarshal(decrypted_bytes, &server_resp)
	server_msg_bytes, _ := json.Marshal(server_resp.Msg)
	if !crypto_utils.Verify(server_resp.Sig, crypto_utils.Hash(server_msg_bytes), serverPublicKey) {
		return false
	}
	// check message stuff now
	if string(original_msg.Client) != string(server_resp.Msg.Client) || string(original_msg.Uid) != string(server_resp.Msg.Uid) || original_msg.Tod.GoString() != server_resp.Msg.Tod.GoString() {
		return false
	}
	return true
}

func validateRequest(r *Request) bool {
	switch r.Op {
	case REGISTER:
		return r.Pass != "" // cannot register with an empty password
	case CREATE, WRITE:
		return r.Key != "" && r.Val != nil && login_attempt != 0
	case DELETE, READ:
		return r.Key != ""
	case COPY:
		return r.Dest_Key != "" && r.Source_Key != "" && login_attempt != 0
	case LOGIN:
		if login_attempt == 0 {
			return true
		}
	case LOGOUT:
		if login_attempt == 1 {
			return true
		}
	case CHANGE_PASS:
		return r.Old_pass != "" && r.New_pass != ""
	default:
		return false
	}
	return false
}

func genEncryptedRequest(request *Client_Message, is_login bool, is_register bool) *Encrypted_Request {
	var enc_req Encrypted_Request
	var enc_m_sig []byte
	msg, _ := json.Marshal(request)
	sig := crypto_utils.Sign(msg, clientSigPrivKey)
	m_sig_bytes, _ := json.Marshal(Signed_Client_Message{Msg: *request, Sig: sig})
	if is_register {
		enc_m_sig = crypto_utils.EncryptSK(m_sig_bytes, request.One_Time_Key)
	} else {
		enc_m_sig = crypto_utils.EncryptSK(m_sig_bytes, sessionKey)
	}
	if is_login {
		enc_key := crypto_utils.EncryptPK(sessionKey, serverPublicKey)
		enc_req = Encrypted_Request{Client: name, Enc_Signed_M: enc_m_sig, Enc_Shared_Key: enc_key}
	} else {
		enc_req = Encrypted_Request{Client: name, Enc_Signed_M: enc_m_sig}
	}
	return &enc_req
}

func doOp(request *Encrypted_Request, response *Encrypted_Response) {
	requestBytes, _ := json.Marshal(request)
	json.Unmarshal(sendAndReceive(NetworkData{Payload: requestBytes, Name: name}).Payload, &response)

}

func sendAndReceive(toSend NetworkData) NetworkData {
	Requests <- toSend
	return <-Responses
}
