package main

import (
	"os"
	"fmt"
	"net"
	"bufio"
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

func SetUsername() string{
	var username string
	fmt.Printf("Quel nom d'utilisateur : ")
	fmt.Scan(&username)
	return username
}

func Connect(server string) net.Conn{
	connection, err := net.Dial("tcp", server)
	if err != nil {
		fmt.Println("Could not connect")
		os.Exit(1)
	}
	return connection
}

func Encryption(message string, server_pub_key rsa.PublicKey) string {
	data := []byte(message)

	// crypto/rand.Reader is a good source of entropy for randomizing the
	// encryption function.
	rng := rand.Reader

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, &server_pub_key, data, nil)
	if err != nil {
		fmt.Printf("Error from encryption: %s\n", err)
		return "fuck"
	}
	return string(ciphertext)
}

func Decryption(message string, user_priv_key rsa.PrivateKey) string {
	data := []byte(message)
	rng := rand.Reader

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, &user_priv_key, data, nil)
	if err != nil {
		fmt.Printf("Error from decryption: %s\n", err)
		return "fuck"
	}
	return string(plaintext)

}

func main(){
	arguments := os.Args
	if len(arguments) == 1 {
			fmt.Println("Please provide host:port.")
			os.Exit(1)
	}
	server := arguments[1]
	username := SetUsername()
	user_pub_key, _ := KeyGen()
	var server_pub_key = rsa.PublicKey{}

	connection := Connect(server)
	enc := gob.NewEncoder(connection)
    dec := gob.NewDecoder(connection)
	enc.Encode(&user_pub_key)
	dec.Decode(&server_pub_key)
	enc.Encode(Encryption(username, server_pub_key))
	
	for {
		scanner := bufio.NewScanner(os.Stdin)
		fmt.Printf("%s >> ", username)
		scanner.Scan()
		enc.Encode(Encryption(scanner.Text(), server_pub_key))
	}
}