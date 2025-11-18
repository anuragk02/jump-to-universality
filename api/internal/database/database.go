package database

import (
	"context"
	"log"
	"os"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type DB struct {
	driver neo4j.DriverWithContext
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

	return &DB{driver: driver}
}

func (db *DB) Close(ctx context.Context) error {
	return db.driver.Close(ctx)
}

func (db *DB) ExecuteQuery(ctx context.Context, query string, params map[string]interface{}) (neo4j.ResultWithContext, error) {
	session := db.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	return session.Run(ctx, query, params)
}

func (db *DB) ExecuteRead(ctx context.Context, query string, params map[string]interface{}) ([]map[string]interface{}, error) {
	session := db.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	result, err := session.Run(ctx, query, params)
	if err != nil {
		return nil, err
	}
	
	var records []map[string]interface{}
	for result.Next(ctx) {
		record := result.Record()
		recordMap := make(map[string]interface{})
		for i, key := range record.Keys {
			recordMap[key] = record.Values[i]
		}
		records = append(records, recordMap)
	}

	return records, result.Err()
}