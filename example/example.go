package main

import (
	goauth "go-auth"
	"log"
	"time"
)

func main() {
	salt := "098f6bcd4621d373cade4e832627b4f6"
	expiry := time.Now().UTC().Add(time.Hour * 24 * 30).Unix()
	userID := "sampleID"

	client := goauth.New(salt, expiry)
	token, err := client.Encode(userID)
	if err != nil {
		panic(err)
	}
	log.Printf("Encoded token is: %s", token)

	ID, err := client.Decode(token)
	if err != nil {
		panic(err)
	}
	log.Printf("Decoded userID is: %s", ID)
}
