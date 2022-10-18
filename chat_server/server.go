package main

import (
	"os"
	"fmt"
	"net"
	"crypto/rsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"runtime"
)

var message = make(chan string)


func Banner(){
	// A banner for fun
	fmt.Println("# #     #   # ######### ##########   ######     ######              #            ######   #   #   ######   \n #   #  #   #         #          #                #                 #   ###        #      #   #            \n# # #   #   #         #         #  ########## ##########   ##       ####       ########## #   # ########## \n   #    #   # ########  ########   #        #     #       #  ##     #              #      #   # #        # \n  # #      #         #      ##            ##      #      #     ##   #              #         #         ##  \n #   #    #          #    ##            ##        #              ## #              #        #        ##    \n      # ##    ########  ##            ##           ####              #######        ####  ##       ##")
	fmt.Println("Gomunicazion server permitts you to host private conversation via tcp logging is enabled by default though, enjoy !")
}

func KeyGen() (rsa.PublicKey, rsa.PrivateKey){
	// key generation
	priv_key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fmt.Println("Could not generate Keys")
		os.Exit(1)
	}
	pub_key := priv_key.PublicKey
	return pub_key, *priv_key
}

func Encryption(message string, user_pub_key rsa.PublicKey) string {
	//Encrypt outgoing data
	data := []byte(message)
	rng := rand.Reader

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, &user_pub_key, data, nil)
	if err != nil {
		fmt.Printf("Error from encryption: %s\n", err)
		return "fuck"
	}
	return string(ciphertext)
}

func Decryption(message string, server_priv_key rsa.PrivateKey) string {
	//Decrypt incoming data
	data := []byte(message)
	rng := rand.Reader

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, &server_priv_key, data, nil)
	if err != nil {
		fmt.Printf("Error from decryption: %s\n", err)
		return "fuck"
	}
	return string(plaintext)

}

func MessageHandler(connection net.Conn, user_pub_key rsa.PublicKey){
	//A goroutine to send data to users
	enc := gob.NewEncoder(connection)
	for {
		new_message := <-message
		data := Encryption(new_message, user_pub_key)
		enc.Encode(&data)
	}
}

func ConnectionHandler(connection net.Conn, server_pub_key rsa.PublicKey, server_priv_key rsa.PrivateKey){
	//A goroutine to receive data from users
	fmt.Printf("Handling %s\n", connection.RemoteAddr().String())
	var username string
	var user_pub_key = rsa.PublicKey{}

	//We use gob encoding in order to transmit and receive data safely
	enc := gob.NewEncoder(connection)
    dec := gob.NewDecoder(connection)

	//Big dumb key exchange
	dec.Decode(&user_pub_key)
	enc.Encode(&server_pub_key)
	go MessageHandler(connection, user_pub_key)
	for {
		var recieved_data string
		dec.Decode(&recieved_data)
		if username == ""{
			//If username is not set the the data is the username
			username = Decryption(recieved_data, server_priv_key)
			fmt.Printf("User %s connected on %s\n",username , connection.RemoteAddr().String())
		} else {
			//Else data must be sent to users
			recieved_data = Decryption(recieved_data, server_priv_key)
			fmt.Printf("%s @ %s said : %s \n",username , connection.RemoteAddr().String(), recieved_data)
			data_to_send := username+" : "+recieved_data
			for i := 0; i < runtime.NumGoroutine()/2; i++ {
				//Adding the data for all MessageHandler goroutines running
				message <- data_to_send
			}
		}
	}
	connection.Close()
}

func main(){
	Banner()
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