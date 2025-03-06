package network

import (
	"client"
	"server"
	"types"
)

var old_request types.NetworkData
var old_response types.NetworkData

func init() {
	client.ObtainServerPublicKey()
	go relayWithAttacker()
}

func relayWithAttacker() {
	defer close(server.Requests)
	defer close(client.Responses)
	count := 0
	for request := range client.Requests {

		modifiedRequest := request
		// Modifying request attack
		if count%4 == 0 {
			modifiedPayload := modifyMessage(request.Payload)
			modifiedRequest = types.NetworkData{Name: request.Name, Payload: modifiedPayload}
		}
		server.Requests <- modifiedRequest

		response := <-server.Responses
		modifiedResponse := response

		// Modifying response attack
		if count%4 == 1 {
			modifiedPayload := modifyMessage(response.Payload)
			modifiedResponse = types.NetworkData{Name: response.Name, Payload: modifiedPayload}
		}
		// Send the response back to the client
		client.Responses <- modifiedResponse

		// Replay attack of old request
		if count%4 == 2 {
			server.Requests <- old_request
			client.Responses <- (<-server.Responses)
		}

		// Replay attack of old response
		if count%4 == 3 {
			server.Requests <- modifiedRequest
			client.Responses <- old_response
		}

		old_request = request
		old_response = response
		count++
	}
}

// modifyMessage alters a message
func modifyMessage(msg []byte) []byte {
	if len(msg) > 0 {
		msg[len(msg)-1] ^= 0xFF // Flip the last byte to corrupt the message
	}
	return msg
}
