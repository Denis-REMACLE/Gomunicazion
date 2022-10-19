package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/gob"
	"strconv"
	"fmt"
	"net"
	"os"
	"runtime"
)

var message = make(chan string)

func Banner() {
	// A banner for fun
	fmt.Println("# #     #   # ######### ##########   ######     ######              #            ######   #   #   ######   \n #   #  #   #         #          #                #                 #   ###        #      #   #            \n# # #   #   #         #         #  ########## ##########   ##       ####       ########## #   # ########## \n   #    #   # ########  ########   #        #     #       #  ##     #              #      #   # #        # \n  # #      #         #      ##            ##      #      #     ##   #              #         #         ##  \n #   #    #          #    ##            ##        #              ## #              #        #        ##    \n      # ##    ########  ##            ##           ####              #######        ####  ##       ##")
	fmt.Println("Gomunicazion server permitts you to host private conversation via tcp logging is enabled by default though, enjoy !")
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

func Encryption(message string, user_pub_key rsa.PublicKey) string {
	//Encrypt outgoing data
	data := []byte(message)
	rng := rand.Reader

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, &user_pub_key, data, nil)
	if err != nil {
		fmt.Printf("Error from encryption: %s\n", err)
		return "Encryption error"
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
		return "Decryption error"
	}
	return string(plaintext)

}

func split(tosplit string, sep rune) []string {
	//string splitting function

	var fields []string
	last := 0
	
	for i,c := range tosplit {
        	if c == sep {
        	// Found the separator, append a slice
        	fields = append(fields, string(tosplit[last:i]))
        	last = i + 1
		}
	}

	// Don't forget the last field
	fields = append(fields, string(tosplit[last:]))

	return fields
}

func MessageHandler(connection net.Conn, user_pub_key rsa.PublicKey) {
	//A goroutine to send data to users
	enc := gob.NewEncoder(connection)
	for {
		new_message := <-message
		if split(new_message, ' ')[0] == "Decryption" && split(new_message, ' ')[2] == connection.RemoteAddr().String(){
			break
		} else {
			data := Encryption(new_message, user_pub_key)
			enc.Encode(&data)
		}
	}
}

func ConnectionHandler(connection net.Conn, server_pub_key rsa.PublicKey, server_priv_key rsa.PrivateKey) {
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
		if username == "" {
			//If username is not set the the data is the username
			username = Decryption(recieved_data, server_priv_key)
			fmt.Printf("User %s connected on %s\n", username, connection.RemoteAddr().String())
		} else {
			//Else data must be sent to users
			recieved_data = Decryption(recieved_data, server_priv_key)
			if recieved_data == "Decryption error" {
				for i := 0; i < runtime.NumGoroutine()/2; i++ {
					message  <- recieved_data+" "+connection.RemoteAddr().String()
				}
				break
			}
			fmt.Printf("%s @ %s said : %s \n", username, connection.RemoteAddr().String(), recieved_data)
			data_to_send := username + " : " + recieved_data
			for i := 0; i < runtime.NumGoroutine()/2; i++ {
				//Adding the data for all MessageHandler goroutines running
				message <- data_to_send
			}
		}
	}
	connection.Close()
}

func main() {
	Banner()
	arguments := os.Args
	port := arguments[1]
	max_clients, _ := strconv.Atoi(arguments[2])
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
		if runtime.NumGoroutine() / 2 == max_clients {
			fmt.Println("Can't handle more clients")
		} else {
			go ConnectionHandler(connection, server_pub_key, server_priv_key)
		}
	}
}
