package server

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"os"
	"slices"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"

	"crypto_utils"
	. "types"
)

var SALT_SIZE = 10
var privateKey *rsa.PrivateKey
var publicKey *rsa.PublicKey

var name string
var kvstore map[string]Key_MetaData // maps Key to Key_Metadata struct
var Requests chan NetworkData
var Responses chan NetworkData

var session_running bool
var binding_table map[string]Binding_Table_Entry   // maps Client to associated entry in binding table
var password_table map[string]Password_Table_Entry // maps uid to associated entry in password table
var sev_response Server_Message

func init() {
	privateKey = crypto_utils.NewPrivateKey()
	publicKey = &privateKey.PublicKey
	publicKeyBytes := crypto_utils.PublicKeyToBytes(publicKey)
	if err := os.WriteFile("SERVER_PUBLICKEY", publicKeyBytes, 0666); err != nil {
		panic(err)
	}

	name = uuid.NewString()
	session_running = false
	kvstore = make(map[string]Key_MetaData)
	Requests = make(chan NetworkData)
	Responses = make(chan NetworkData)
	binding_table = make(map[string]Binding_Table_Entry)
	password_table = make(map[string]Password_Table_Entry)

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
	//fmt.Println("server 72 set uid to ", sev_response.Uid)
	sev_response.S_Response = *response
	is_logout := request.Request.Op == LOGOUT
	failed_changepass := (request.Request.Op == CHANGE_PASS) && (response.Status == FAIL)
	is_register := request.Request.Op == REGISTER
	enc_response := genEncryptedResponse(&sev_response, is_logout, failed_changepass, sk, is_register)
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
	//fmt.Println("server 89 set uid to ", response.Uid)
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
		case CHANGE_PASS:
			doCHANGE_PASS(c_msg, response)
		case MODACL:
			doMODACL(&c_msg.Request, response)
		case REVACL:
			doREVACL(&c_msg.Request, response)

		default: //LOGIN, REGISTER will fall through to fail
			// struct already default initialized to
			// FAIL status
		}
	} else {
		switch c_msg.Request.Op {
		case LOGIN:
			doLOGIN(c_msg, response, sk)
		case REGISTER:
			doRegister(c_msg, response)
		}
	}
}

/** begin operation methods **/
// Input: src_key s, dest_key d. Returns a response.
// Copies the value from key s over to key d
func doCopy(request *Request, response *Response) {
	if s, ok := kvstore[request.Source_Key]; ok {
		if d, ok2 := kvstore[request.Dest_Key]; ok2 {
			src_acl := generateACL(s, "c_src(k)")
			dst_acl := generateACL(d, "c_dst(k)")
			if slices.Contains(src_acl, request.Uid) && slices.Contains(dst_acl, request.Uid) {
				d.Val = s.Val
				kvstore[request.Dest_Key] = d
				response.Status = OK
			}
		}
	}
}

// Input: key k, value v, metaval m. Returns a response.
// Sets the value and metaval for key k in the
// key-value store to value v and metavalue m.
func doCreate(request *Request, response *Response) {
	if _, ok := kvstore[request.Key]; !ok {
		new_key := Key_MetaData{Val: request.Val, Writers: request.Writers,
			Readers: request.Readers, Copyfroms: request.Copyfroms, Copytos: request.Copytos,
			Indirects: request.Indirects, Owner: request.Uid}
		kvstore[request.Key] = new_key
		response.Status = OK
	}
}

// Input: key k. Returns a response. Deletes key from
// key-value store. If key does not exist then take no
// action.
func doDelete(request *Request, response *Response) {
	if k, ok := kvstore[request.Key]; ok {
		if request.Uid == k.Owner {
			delete(kvstore, request.Key)
			response.Status = OK
		}
	}
}

// Input: key k. Returns a response with the value
// associated with key. If key does not exist
// then status is FAIL.
func doReadVal(request *Request, response *Response) {
	if k, ok := kvstore[request.Key]; ok {
		read_acl := generateACL(k, "r(k)")
		if slices.Contains(read_acl, request.Uid) {
			response.Val = k.Val
			response.Status = OK
		}
	}
}

// Input: key k and value v. Returns a response.
// Change value in the key-value store associated
// with key k to value v. If key does not exist
// then status is FAIL.
func doWriteVal(request *Request, response *Response) {
	if k, ok := kvstore[request.Key]; ok {
		write_acl := generateACL(k, "w(k)")
		if slices.Contains(write_acl, request.Uid) {
			k.Val = request.Val
			kvstore[request.Key] = k
			response.Status = OK
		}
	}
}

// new_key := Key_MetaData{Val: request.Val, Writers: request.Writers,
// 	Readers: request.Readers, Copyfroms: request.Copyfroms, Copytos: request.Copytos,
// 	Indirects: request.Indirects, Owner: request.Uid}

func doMODACL(request *Request, response *Response) {
	if k, ok := kvstore[request.Key]; ok {
		if request.Uid == k.Owner {
			if request.Writers != nil {
				k.Writers = request.Writers
			}
			if request.Readers != nil {
				k.Readers = request.Readers
			}
			if request.Copyfroms != nil {
				k.Copyfroms = request.Copyfroms
			}
			if request.Copytos != nil {
				k.Copytos = request.Copytos
			}
			if request.Indirects != nil {
				k.Indirects = request.Indirects
			}
			kvstore[request.Key] = k
			response.Status = OK
		}
	}
}

func doREVACL(request *Request, response *Response) {
	if k, ok := kvstore[request.Key]; ok {
		if request.Uid == k.Owner {
			response.Status = OK
			response.Writers = k.Writers
			response.Readers = k.Readers
			response.Copytos = k.Copytos
			response.Copyfroms = k.Copyfroms
			response.Indirects = k.Indirects
			response.R_k = generateACL(k, "r(k)")
			response.W_k = generateACL(k, "w(k)")
			response.C_src_k = generateACL(k, "c_src(k)")
			response.C_dst_k = generateACL(k, "c_dst(k)")
		}
	}
}

func doLOGIN(c_msg *Client_Message, response *Response, sk []byte) {
	session_running = true
	response.Status = OK
	bind_table := Binding_Table_Entry{Uid: c_msg.Uid, Tod: c_msg.Tod, Shared_key: sk}
	binding_table[string(c_msg.Client)] = bind_table
	if entry, ok := password_table[string(c_msg.Uid)]; ok {
		var pass = entry.Hashpass
		if !bytes.Equal(pass, argon2.Key([]byte(c_msg.Request.Pass), entry.Salt, 1, 64*1024, 4, 32)) {
			response.Status = FAIL
			session_running = false
		}
	} else {
		response.Status = FAIL
		session_running = false
	}

}

func doRegister(c_msg *Client_Message, response *Response) {
	if _, ok := password_table[string(c_msg.Request.Uid)]; ok {
		response.Status = FAIL
	} else {
		salt := crypto_utils.RandomBytes(SALT_SIZE)
		hash_pass := argon2.Key([]byte(c_msg.Request.Pass), salt, 1, 64*1024, 4, 32)
		new_pass := Password_Table_Entry{Hashpass: hash_pass, Salt: salt}

		password_table[string(c_msg.Request.Uid)] = new_pass
		response.Status = OK
	}
}

func doLOGOUT(c_msg *Client_Message, response *Response) {
	session_running = false
	response.Status = OK
}
func doCHANGE_PASS(c_msg *Client_Message, response *Response) {
	// verify KDF(salt, old_pass) == uid.salted_pass
	if entry, ok := password_table[string(c_msg.Uid)]; ok {
		var old_pass = entry.Hashpass
		if bytes.Equal(old_pass, argon2.Key([]byte(c_msg.Request.Old_pass), entry.Salt, 1, 64*1024, 4, 32)) {
			// fmt.Println(string(c_msg.Uid))
			new_salt := crypto_utils.RandomBytes(SALT_SIZE)
			var new_pass = argon2.Key([]byte(c_msg.Request.New_pass), new_salt, 1, 64*1024, 4, 32) // use same salt
			var new_password_entry = Password_Table_Entry{Hashpass: new_pass, Salt: new_salt}
			password_table[string(c_msg.Uid)] = new_password_entry
			response.Status = OK

			// TODO: do you update nonces in binding table? looks like client checks if nonces are the same.
		} else {
			response.Status = FAIL // this deletes uid in session table like logout does
			session_running = false

		}
	} else {
		response.Status = FAIL
		session_running = false

	}

}

func decryptAndVerify(enc_request *Encrypted_Request) (*Client_Message, *Response, []byte) {
	//if Enc_Shared_Key field isn't empty, LOGIN ==> decrypt field using public key to obtain shared key
	//else, shared key comes from binding table
	var shared_key []byte
	var response Response
	// check for login or register
	if len(enc_request.Enc_Shared_Key) != 0 {
		key, _ := crypto_utils.DecryptPK(enc_request.Enc_Shared_Key, privateKey)
		shared_key = key
	} else {
		entry, _ := binding_table[string(enc_request.Client)]
		shared_key = entry.Shared_key
	}

	//use shared key to decrypt signed message into message and signature
	signed_m, _ := crypto_utils.DecryptSK(enc_request.Enc_Signed_M, shared_key)
	var s_msg Signed_Client_Message
	json.Unmarshal(signed_m, &s_msg)
	sig := s_msg.Sig
	c_msg := s_msg.Msg
	msg, _ := json.Marshal(c_msg)
	//obtain public signature key from client from message to verify signature
	sig_pub_key, err := crypto_utils.BytesToPublicKey(c_msg.Sig_Pub_Key)
	if err != nil || sig_pub_key == nil {
		response.Status = FAIL
		return &c_msg, &response, shared_key
	}
	verify := crypto_utils.Verify(sig, crypto_utils.Hash(msg), sig_pub_key)

	//verify plaintext client and tod
	if string(c_msg.Client) != string(enc_request.Client) {
		verify = false
	}

	// probably want to switch this to a switch statement when implementing rest
	if c_msg.Request.Op != REGISTER {
		entry, _ := binding_table[string(c_msg.Client)]
		tableTod := entry.Tod
		if c_msg.Tod.Compare(tableTod) == -1 && c_msg.Request.Op != LOGIN {
			verify = false
		}
		if c_msg.Tod.Compare(crypto_utils.ReadClock()) != -1 {
			verify = false
		}
	} else {
		// is a register, if in password_table then fail
		if _, ok := password_table[c_msg.Uid]; ok {
			verify = false
		}
	}

	//return decrypted request from m and response indicating status of authentication
	if verify {
		response.Status = OK
	} else {
		response.Status = FAIL
	}
	return &c_msg, &response, shared_key
}

func genEncryptedResponse(response *Server_Message, is_logout bool, failed_changepass bool, register_key []byte, is_register bool) *Encrypted_Response {
	msg, _ := json.Marshal(response)
	sig := crypto_utils.Sign(msg, privateKey)
	m_sig, _ := json.Marshal(Signed_Server_Message{Msg: *response, Sig: sig})
	var enc_m_sig []byte
	if is_register || !session_running {
		enc_m_sig = crypto_utils.EncryptSK(m_sig, register_key)
	} else {
		enc_m_sig = crypto_utils.EncryptSK(m_sig, binding_table[string(response.Client)].Shared_key)
	}
	enc_res := Encrypted_Response{Server: name, Enc_Signed_M: enc_m_sig}
	if is_logout || failed_changepass {
		delete(binding_table, string(response.Client))
	}
	return &enc_res
}

func generateACL(k Key_MetaData, acl_type string) []string {
	var direct []string

	switch acl_type {
	case "r(k)":
		direct = k.Readers
	case "w(k)":
		direct = k.Writers
	case "c_dst(k)":
		direct = k.Copytos
	case "c_src(k)":
		direct = k.Copyfroms
	}
	acl_result := make(map[string]int)
	for _, principal := range direct {
		acl_result[principal] = 0
	}

	for _, i_key := range k.Indirects {
		i_key_metadata, _ := kvstore[i_key]
		i_principals := generateACL(i_key_metadata, acl_type)
		for _, principal := range i_principals {
			acl_result[principal] = 0 //no op if already exists
		}
	}

	keys := make([]string, len(acl_result))
	i := 0
	for k := range acl_result {
		keys[i] = k
		i++
	}
	return keys
}
