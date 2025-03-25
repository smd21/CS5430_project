package server

import (
	"crypto/rsa"
	"encoding/json"
	"os"

	"github.com/google/uuid"

	"crypto_utils"
	. "types"
)

var SALT_SIZE = 10
var privateKey *rsa.PrivateKey
var publicKey *rsa.PublicKey
var salt []byte

var name string
var kvstore map[string]interface{}
var Requests chan NetworkData
var Responses chan NetworkData

var session_running bool
var binding_table map[string]Binding_Table_Entry   // maps Client to associated entry in binding table
var password_table map[string]Password_Table_Entry // maps Client to hashed password
var sev_response Server_Message

func init() {
	privateKey = crypto_utils.NewPrivateKey()
	publicKey = &privateKey.PublicKey
	salt = crypto_utils.RandomBytes(SALT_SIZE)
	publicKeyBytes := crypto_utils.PublicKeyToBytes(publicKey)
	if err := os.WriteFile("SERVER_PUBLICKEY", publicKeyBytes, 0666); err != nil {
		panic(err)
	}

	name = uuid.NewString()
	session_running = false
	kvstore = make(map[string]interface{})
	Requests = make(chan NetworkData)
	Responses = make(chan NetworkData)
	binding_table = make(map[string]Binding_Table_Entry)

	go receiveThenSend()
}

func receiveThenSend() {
	defer close(Responses)

	for request := range Requests {
		Responses <- process(request)
	}
}

// Input: a byte array representing a request from a client.
// Deserializes the byte array into a request and performs
// the corresponding operation. Returns the serialized
// response. This method is invoked by the network.
func process(requestData NetworkData) NetworkData {
	var enc_request Encrypted_Request
	json.Unmarshal(requestData.Payload, &enc_request)
	request, response, sk := decryptAndVerify(&enc_request)
	// before doOp check to see if respone has already failed, means authentication failed
	if response.Status != FAIL {
		doOp(request, response, sk)
	}
	sev_response.Tod = request.Tod
	sev_response.Client = request.Client
	sev_response.Uid = request.Uid
	sev_response.S_Response = *response
	is_logout := request.Request.Op == LOGOUT
	enc_response := genEncryptedResponse(&sev_response, is_logout)
	responseBytes, _ := json.Marshal(enc_response)
	return NetworkData{Payload: responseBytes, Name: name}
}

// Input: request from a client. Returns a response.
// Parses request and handles a switch statement to
// return the corresponding response to the request's
// operation.
func doOp(c_msg *Client_Message, response *Response, sk []byte) {
	response.Status = FAIL
	response.Uid = c_msg.Request.Uid
	if session_running {
		switch c_msg.Request.Op {
		case NOOP:
			// NOTHING
		case CREATE:
			doCreate(&c_msg.Request, response)
		case DELETE:
			doDelete(&c_msg.Request, response)
		case READ:
			doReadVal(&c_msg.Request, response)
		case WRITE:
			doWriteVal(&c_msg.Request, response)
		case COPY:
			doCopy(&c_msg.Request, response)
		case LOGOUT:
			doLOGOUT(c_msg, response)

		default: //LOGIN will fall through to fail
			// struct already default initialized to
			// FAIL status
		}
	} else {
		if c_msg.Request.Op == LOGIN {
			doLOGIN(c_msg, response, sk)
		}
	}
}

/** begin operation methods **/
// Input: src_key s, dest_key d. Returns a response.
// Copies the value from key s over to key d
func doCopy(request *Request, response *Response) {
	if _, ok := kvstore[request.Source_Key]; ok {
		if _, ok2 := kvstore[request.Dest_Key]; ok2 {
			kvstore[request.Dest_Key] = kvstore[request.Source_Key]
			response.Status = OK
		}
	}
}

// Input: key k, value v, metaval m. Returns a response.
// Sets the value and metaval for key k in the
// key-value store to value v and metavalue m.
func doCreate(request *Request, response *Response) {
	if _, ok := kvstore[request.Key]; !ok {
		kvstore[request.Key] = request.Val
		response.Status = OK
	}
}

// Input: key k. Returns a response. Deletes key from
// key-value store. If key does not exist then take no
// action.
func doDelete(request *Request, response *Response) {
	if _, ok := kvstore[request.Key]; ok {
		delete(kvstore, request.Key)
		response.Status = OK
	}
}

// Input: key k. Returns a response with the value
// associated with key. If key does not exist
// then status is FAIL.
func doReadVal(request *Request, response *Response) {
	if v, ok := kvstore[request.Key]; ok {
		response.Val = v
		response.Status = OK
	}
}

// Input: key k and value v. Returns a response.
// Change value in the key-value store associated
// with key k to value v. If key does not exist
// then status is FAIL.
func doWriteVal(request *Request, response *Response) {
	if _, ok := kvstore[request.Key]; ok {
		kvstore[request.Key] = request.Val
		response.Status = OK
	}
}

func doLOGIN(c_msg *Client_Message, response *Response, sk []byte) {
	session_running = true
	response.Status = OK

	bind_table := Binding_Table_Entry{Uid: c_msg.Uid, Tod: c_msg.Tod, Shared_key: sk}
	binding_table[string(c_msg.Client)] = bind_table
}

func doLOGOUT(c_msg *Client_Message, response *Response) {
	session_running = false
	response.Status = OK
}

func decryptAndVerify(enc_request *Encrypted_Request) (*Client_Message, *Response, []byte) {
	//if Enc_Shared_Key field isn't empty, LOGIN ==> decrypt field using public key to obtain shared key
	//else, shared key comes from binding table
	var shared_key []byte
	if len(enc_request.Enc_Shared_Key) != 0 {
		key, err := crypto_utils.DecryptPK(enc_request.Enc_Shared_Key, privateKey)
		if err == nil {
			shared_key = key
		}
	} else {
		if entry, ok := binding_table[string(enc_request.Client)]; ok {
			shared_key = entry.Shared_key
		}
	}
	//use shared key to decrypt signed message into message and signature
	signed_m, _ := crypto_utils.DecryptSK(enc_request.Enc_Signed_M, shared_key)
	var s_msg Signed_Client_Message
	json.Unmarshal(signed_m, &s_msg)
	sig := s_msg.Sig
	c_msg := s_msg.Msg
	msg, _ := json.Marshal(c_msg)

	//obtain public signature key from client from message to verify signature
	sig_pub_key, _ := crypto_utils.BytesToPublicKey(c_msg.Sig_Pub_Key)
	verify := crypto_utils.Verify(sig, crypto_utils.Hash(msg), sig_pub_key)

	sev_response.Client = c_msg.Client
	sev_response.Uid = c_msg.Uid
	//verify plaintext client and tod
	if string(c_msg.Client) != string(enc_request.Client) {
		verify = false
	}
	entry, _ := binding_table[string(c_msg.Client)]
	tableTod := entry.Tod
	if c_msg.Tod.Compare(tableTod) == -1 && c_msg.Request.Op != LOGIN {
		verify = false
	}
	if c_msg.Tod.Compare(crypto_utils.ReadClock()) != -1 {
		verify = false
	}

	//return decrypted request from m and response indicating status of authentication
	var response Response
	if verify {
		response.Status = OK
	} else {
		response.Status = FAIL
	}
	return &c_msg, &response, shared_key
}

func genEncryptedResponse(response *Server_Message, is_logout bool) *Encrypted_Response {
	msg, _ := json.Marshal(response)
	sig := crypto_utils.Sign(msg, privateKey)
	m_sig, _ := json.Marshal(Signed_Server_Message{Msg: *response, Sig: sig})
	enc_m_sig := crypto_utils.EncryptSK(m_sig, binding_table[string(response.Client)].Shared_key)
	enc_res := Encrypted_Response{Server: name, Enc_Signed_M: enc_m_sig}
	if is_logout {
		delete(binding_table, string(response.Client))
	}
	return &enc_res
}
