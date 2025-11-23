package database

import (
	"context"
	"log"
	"os"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type DB struct {
	Driver neo4j.DriverWithContext
}

func NewDB() *DB {
	uri := os.Getenv("NEO4J_URI")
	if uri == "" {
		log.Fatal("NEO4J_URI environment variable is required")
	}

	user := os.Getenv("NEO4J_USER")
	if user == "" {
		log.Fatal("NEO4J_USER environment variable is required")
	}

	password := os.Getenv("NEO4J_PASSWORD")
	if password == "" {
		log.Fatal("NEO4J_PASSWORD environment variable is required")
	}

	driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(user, password, ""))
	if err != nil {
		log.Fatal("Failed to create Neo4j driver:", err)
	}

	return &DB{Driver: driver}
}

func (db *DB) Close(ctx context.Context) error {
	return db.Driver.Close(ctx)
}