package main

import (
	"fmt"
	"os"
	"log"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Please provide a password as an argument")
	}
	password := os.Args[1]

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal("Failed to hash password:", err)
	}

	// This line must ONLY print the hash
	fmt.Print(string(hashedPassword))
}