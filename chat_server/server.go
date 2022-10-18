package main

import (
	"os"
	"fmt"
	"net"
	"crypto/rsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
)

func KeyGen() (rsa.PublicKey, rsa.PrivateKey){
	priv_key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fmt.Println("Could not generate Keys")
		os.Exit(1)
	}
	pub_key := priv_key.PublicKey
	return pub_key, *priv_key
}

func Encryption(message string, user_pub_key rsa.PublicKey) string {
	data := []byte(message)

	// crypto/rand.Reader is a good source of entropy for randomizing the
	// encryption function.
	rng := rand.Reader

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, &user_pub_key, data, nil)
	if err != nil {
		fmt.Printf("Error from encryption: %s\n", err)
		return "fuck"
	}
	return string(ciphertext)
}

func Decryption(message string, server_priv_key rsa.PrivateKey) string {
	data := []byte(message)
	rng := rand.Reader

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, &server_priv_key, data, nil)
	if err != nil {
		fmt.Printf("Error from decryption: %s\n", err)
		return "fuck"
	}
	return string(plaintext)

}


func ConnectionHandler(connection net.Conn, server_pub_key rsa.PublicKey, server_priv_key rsa.PrivateKey){
	fmt.Printf("Handling %s\n", connection.RemoteAddr().String())
	enc := gob.NewEncoder(connection)
    dec := gob.NewDecoder(connection)
	var username string
	var user_pub_key = rsa.PublicKey{}
	dec.Decode(&user_pub_key)
	enc.Encode(&server_pub_key)
	for {
		var recieved_data string
		dec.Decode(&recieved_data)
		if username == ""{
			username = Decryption(recieved_data, server_priv_key)
			fmt.Printf("User %s connected on %s\n",username , connection.RemoteAddr().String())
		} else {
			recieved_data = Decryption(recieved_data, server_priv_key)
			//message := username+" : "+recieved_data
			fmt.Printf("%s @ %s said : %s \n",username , connection.RemoteAddr().String(), recieved_data)
		}
	}
	connection.Close()
}

func main(){
	port := "127.0.0.1:42069"
	server_pub_key, server_priv_key := KeyGen()
	listener, err := net.Listen("tcp", port)
	if err != nil {
		fmt.Println("Could not start server")
		os.Exit(1)
	}
	defer listener.Close()

	for {
		connection, err := listener.Accept()
		if err != nil {
			fmt.Println("Could not Accept connection")
			return
		}
		
		go ConnectionHandler(connection, server_pub_key, server_priv_key)
	}
}