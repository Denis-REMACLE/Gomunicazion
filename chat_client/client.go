package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"net"
	"os"
)

func Banner() {
	// A banner for fun
	fmt.Println("  ___                               _                    _              \n / __|  ___   _ __    _  _   _ _   (_)  __   __ _   ___ (_)  ___   _ _  \n| (_ | / _ \\ | '  \\  | || | | ' \\  | | / _| / _` | |_ / | | / _ \\ | ' \\ \n \\___| \\___/ |_|_|_|  \\_,_| |_||_| |_| \\__| \\__,_| /__| |_| \\___/ |_||_|")
	fmt.Println("\nGomunicazion permitts you to comunicate privately, enjoy !")
	fmt.Println("Made By Denis <cr1ng3> REMACLE\n")
}

func KeyGen() (rsa.PublicKey, rsa.PrivateKey) {
	// key generation
	priv_key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fmt.Println("Could not generate Keys")
		os.Exit(1)
	}
	pub_key := priv_key.PublicKey
	return pub_key, *priv_key
}

func SetUsername() string {
	//setting up username
	var username string
	fmt.Printf("Please set your username : ")
	fmt.Scan(&username)
	return username
}

func Connect(server string) net.Conn {
	//Connection to server
	connection, err := net.Dial("tcp", server)
	if err != nil {
		fmt.Printf("Could not connect: %s\n", err)
		os.Exit(1)
	}
	return connection
}

func Encryption(message string, server_pub_key rsa.PublicKey) string {
	//Encrypt outgoing data
	data := []byte(message)
	rng := rand.Reader

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, &server_pub_key, data, nil)
	if err != nil {
		fmt.Printf("Error from encryption: %s\n", err)
		return "fuck"
	}
	return string(ciphertext)
}

func Decryption(message string, user_priv_key rsa.PrivateKey) string {
	//Decrypt incoming data
	data := []byte(message)
	rng := rand.Reader

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, &user_priv_key, data, nil)
	if err != nil {
		fmt.Printf("Error from decryption: %s\n", err)
		return "fuck"
	}
	return string(plaintext)

}

func Receiver(connection net.Conn, user_priv_key rsa.PrivateKey, username string) {
	//Goroutine in order to catch incomming messages
	dec := gob.NewDecoder(connection)
	for {
		var message string
		dec.Decode(&message)
		fmt.Printf("\n======New Message======\n%s\n======New Message======\n%s >> ", Decryption(message, user_priv_key), username)
	}
}

func main() {
	Banner()
	arguments := os.Args
	if len(arguments) == 1 {
		fmt.Println("Please provide host:port.")
		os.Exit(1)
	}
	server := arguments[1]
	username := SetUsername()
	user_pub_key, user_priv_key := KeyGen()
	var server_pub_key = rsa.PublicKey{}

	connection := Connect(server)
	//We use gob encoding in order to transmit and receive data safely
	enc := gob.NewEncoder(connection)
	dec := gob.NewDecoder(connection)

	//Big dumb key exchange and sending usename
	enc.Encode(&user_pub_key)
	dec.Decode(&server_pub_key)
	enc.Encode(Encryption(username, server_pub_key))

	//Launching Message handling Gorouting
	go Receiver(connection, user_priv_key, username)

	for {
		//Loop for writing to the server
		scanner := bufio.NewScanner(os.Stdin)
		fmt.Printf("%s >> ", username)
		scanner.Scan()
		enc.Encode(Encryption(scanner.Text(), server_pub_key))
	}
}
