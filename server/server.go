package server

import (
	"crypto/rsa"
	"encoding/json"
	"github.com/google/uuid"
	"os"
	
	"crypto_utils"
	. "types"
)

var privateKey *rsa.PrivateKey 
var publicKey  *rsa.PublicKey

var name string 
var kvstore map[string]interface{}
var Requests chan NetworkData
var Responses chan NetworkData

func init() {
	privateKey = crypto_utils.NewPrivateKey()
	publicKey = &privateKey.PublicKey
	publicKeyBytes := crypto_utils.PublicKeyToBytes(publicKey)
	if err := os.WriteFile("SERVER_PUBLICKEY", publicKeyBytes, 0666); err != nil {
		panic(err)
	}

	name = uuid.NewString()
	kvstore = make(map[string]interface{})
	Requests = make(chan NetworkData)
	Responses = make(chan NetworkData)

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
	var request Request
	json.Unmarshal(requestData.Payload, &request)
	var response Response
	doOp(&request, &response)
	responseBytes, _ := json.Marshal(response)
	return NetworkData{Payload: responseBytes, Name: name}
}

// Input: request from a client. Returns a response.
// Parses request and handles a switch statement to
// return the corresponding response to the request's
// operation.
func doOp(request *Request, response *Response)  {
	response.Status = FAIL
	switch request.Op {
	case NOOP:
		// NOTHING
	case CREATE:
		doCreate(request, response)
	case DELETE:
		doDelete(request, response)
	case READ:
		doReadVal(request, response)
	case WRITE:
		doWriteVal(request, response)
	default:
		// struct already default initialized to
		// FAIL status
	}
}

/** begin operation methods **/
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
