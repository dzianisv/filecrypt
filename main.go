package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/scrypt"
)

const (
	keyLen    = 32 // AES-256
	saltSize  = 16
	nonceSize = 12 // Standard nonce size for AES-GCM
)

func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: cryptotool <encrypt|decrypt> <inputfile> <outputfile>")
		os.Exit(1)
	}

	mode := os.Args[1]
	inputFile := os.Args[2]
	outputFile := os.Args[3]

	fmt.Print("Enter Password: ")
	password, err := bufio.NewReader(os.Stdin).ReadBytes('\n')
	if err != nil {
		fmt.Println("Error reading password:", err)
		return
	}
	password = password[:len(password)-1] // Remove newline

	data, err := ioutil.ReadFile(inputFile)
	if err != nil {
		fmt.Println("Failed to read input file:", err)
		return
	}

	var result []byte
	if mode == "encrypt" {
		result, err = encryptData(data, password)
	} else if mode == "decrypt" {
		result, err = decryptData(data, password)
	} else {
		fmt.Println("Invalid mode. Use 'encrypt' or 'decrypt'.")
		os.Exit(1)
	}

	if err != nil {
		fmt.Println("Failed to process data:", err)
		return
	}

	err = ioutil.WriteFile(outputFile, result, 0644)
	if err != nil {
		fmt.Println("Failed to write output file:", err)
		return
	}

	fmt.Println("Operation completed successfully.")
}

func encryptData(data, password []byte) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	key, err := scrypt.Key(password, salt, 32768, 8, 1, keyLen)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	encrypted := gcm.Seal(nonce, nonce, data, nil)
	return append(salt, encrypted...), nil
}

func decryptData(encryptedData, password []byte) ([]byte, error) {
	if len(encryptedData) < saltSize+nonceSize {
		return nil, fmt.Errorf("encrypted data is too short")
	}

	salt := encryptedData[:saltSize]
	encryptedData = encryptedData[saltSize:]

	key, err := scrypt.Key(password, salt, 32768, 8, 1, keyLen)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := encryptedData[:nonceSize]
	encryptedData = encryptedData[nonceSize:]

	return gcm.Open(nil, nonce, encryptedData, nil)
}
