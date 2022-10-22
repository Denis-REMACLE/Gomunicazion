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

func CheckIP(host string) bool {
	if len(split(host, ':')) != 2 {
		return false
	}

	host_split := split(host, ':')
	count := 0
	ip := split(string(host_split[0]), '.')
	port := string(host_split[1])

	for x := 0; x < len(ip); x++ {

        	if len(ip) != 4 {
        		count++
        		break
            	}

        	tmp := 0
        	tmp, err := strconv.Atoi(ip[x])
        	if err != nil {
        		panic(err)
        		fmt.Println("la valeur entrée n'est pas la bonne")
        		break
        	}
        	if (x == 0 && tmp <= 0 || tmp > 256) || (tmp < 0 || tmp > 256) {
        		count++
        	}
        }
	port_value, _ := strconv.Atoi(port)
	if port_value <= 0 || port_value > 65536 {
		count++
	}
        if count == 0 {
        	return true
        } else {
		return false
	}
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
		return "Encryption error"
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
		return "Decryption error"
	}
	return string(plaintext)

}

func Receiver(connection net.Conn, user_priv_key rsa.PrivateKey, username string) {
	//Goroutine in order to catch incomming messages
	dec := gob.NewDecoder(connection)
	for {
		var message string
		dec.Decode(&message)
		message = Decryption(message, user_priv_key)
		if message == "Decryption error" {
			fmt.Println("\n======= Error ========\nServer has disconnected : quitting !\n======= Error =======")
			os.Exit(0)
		} else {
			fmt.Printf("\n======New Message======\n%s\n======New Message======\n%s >> ", message, username)
		}
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
	if CheckIP(server) == false {
		fmt.Println("Given IP is bad")
		os.Exit(0)
	}
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