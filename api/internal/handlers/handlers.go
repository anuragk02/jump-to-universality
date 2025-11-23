package handlers

import (
	"context"

	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"api/internal/database"
	"api/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	db *database.DB
}

func NewHandler(db *database.DB) *Handler {
	return &Handler{db: db}
}

// // Helper functions for type conversion
// func getStringValue(record map[string]interface{}, key string) string {
// 	if val, ok := record[key]; ok && val != nil {
// 		if str, ok := val.(string); ok {
// 			return str
// 		}
// 	}
// 	return ""
// }

// Health check handler
func (h *Handler) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) LoginHandler(c *gin.Context) {
	var jwtSecretKey = []byte(os.Getenv("JWT_SECRET_KEY"))
	var req models.LoginRequest
	var user models.User

	// 1. Bind the incoming JSON to the LoginRequest struct
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// --- DEBUGGING: Log the received username ---
	// Check your Go console. Does this match 'anurag' EXACTLY?
	// Any whitespace? Different casing?
	log.Printf("Login attempt for username: '%s'", req.Username)

	// 2. Fetch the user from the database (Neo4j)
	query := `MATCH (u:User {username: $username})
              RETURN u.username AS username, u.password AS password`
	params := map[string]interface{}{"username": req.Username}

	result, err := neo4j.ExecuteQuery(context.Background(), h.db.Driver, query, params, neo4j.EagerResultTransformer)
	if err != nil {
		log.Printf("Database query error in LoginHandler: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	// 3. Check if user was found
	if len(result.Records) == 0 {
		log.Printf("Login failed: User '%s' not found.", req.Username)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// 4. Populate user from database record
	record := result.Records[0]
	if username, ok := record.Get("username"); ok {
		user.Username = username.(string)
	}
	if password, ok := record.Get("password"); ok {
		user.Password = password.(string)
	}

	log.Printf("Login: Found user '%s', verifying password...", user.Username)
	log.Printf("Password lengths. DB hash: %d. Received password: %d.", len(user.Password), len(req.Password))

	// 5. Compare the stored hashed password with the incoming password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
	if err != nil {
		// --- DEBUGGING: This is Failure Point 2 ---
		// This means the user was FOUND, but the password was WRONG.
		// This confirms your stored hash is incorrect for the password you sent.
		log.Printf("Login failed: Password mismatch for user '%s' '%s' '%s'.", user.Username, user.Password, req.Password)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// 6. Generate the JWT token
	log.Printf("Login successful for user: %s", user.Username)

	claims := jwt.MapClaims{
		"username": user.Username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
		"iat":      time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecretKey)
	if err != nil {
		log.Println("Error signing token:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	// 7. Send the token back to the user
	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful!",
		"token":   tokenString,
	})
}


// AuthMiddleware creates a gin.HandlerFunc for JWT authentication
func AuthMiddleware() gin.HandlerFunc {
	var jwtSecretKey = []byte(os.Getenv("JWT_SECRET_KEY"))
	return func(c *gin.Context) {
		// 1. Get the Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			log.Println("Auth failed: No Authorization header")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			return
		}

		// 2. Check if it's a Bearer token
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			log.Println("Auth failed: Invalid Authorization header format")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid Authorization header format"})
			return
		}
		tokenString := parts[1]

		// 3. Parse and validate the token
		// We use jwt.Parse to validate the signature and check expiry
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Check the signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			// Return the secret key (must be the same one used in LoginHandler)
			return jwtSecretKey, nil
		})

		if err != nil {
			log.Printf("Auth failed: Invalid token: %v", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		// 4. Check claims and set user ID in context
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			// Extract the userID (or whatever you put in the token)
			username, ok := claims["username"].(string)
			if !ok {
				log.Println("Auth failed: userID claim missing or invalid")
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
				return
			}

			// --- SUCCESS ---
			// Set the userID in the context for other handlers to use
			c.Set("username", username)
			c.Next() // Continue to the next handler
		} else {
			log.Println("Auth failed: Invalid token claims or token is invalid")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		}
	}
}

func (h *Handler) GetProfile(c *gin.Context) {
	// Test handler to verify protected route access
	username, _ := c.Get("username")
	c.JSON(http.StatusOK, gin.H{
		"status":   "ok",
		"username": username,
	})
}

// Essay Handlers

// CreateEssay creates a new essay
func (h *Handler) CreateEssay(c *gin.Context) {
	var req models.CreateEssayRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Get username from auth middleware
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Create essay in Neo4j
	query := `
		MATCH (u:User {username: $username})
		CREATE (e:Essay {
			uuid: randomUUID(),
			title: $title,
			content: $content,
			createdAt: datetime(),
			updatedAt: datetime()
		})
		CREATE (u)-[:AUTHORED]->(e)
		RETURN e.uuid AS uuid, e.title AS title, e.content AS content,
		       e.createdAt AS createdAt, e.updatedAt AS updatedAt
	`
	params := map[string]interface{}{
		"username": username.(string),
		"title":    req.Title,
		"content":  req.Content,
	}

	result, err := neo4j.ExecuteQuery(context.Background(), h.db.Driver, query, params, neo4j.EagerResultTransformer)
	if err != nil {
		log.Printf("Database error creating essay: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create essay"})
		return
	}

	if len(result.Records) == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create essay"})
		return
	}

	record := result.Records[0]
	essay := models.EssayResponse{}
	if uuid, ok := record.Get("uuid"); ok {
		essay.UUID = uuid.(string)
	}
	if title, ok := record.Get("title"); ok {
		essay.Title = title.(string)
	}
	if content, ok := record.Get("content"); ok {
		essay.Content = content.(string)
	}
	if createdAt, ok := record.Get("createdAt"); ok {
		essay.CreatedAt = createdAt.(time.Time)
	}
	if updatedAt, ok := record.Get("updatedAt"); ok {
		essay.UpdatedAt = updatedAt.(time.Time)
	}

	c.JSON(http.StatusCreated, essay)
}

// GetEssay retrieves an essay by UUID
func (h *Handler) GetEssay(c *gin.Context) {
	essayUUID := c.Param("uuid")

	query := `
		MATCH (u:User)-[:AUTHORED]->(e:Essay {uuid: $uuid})
		RETURN e.uuid AS uuid, e.title AS title, e.content AS content,
		       e.createdAt AS createdAt, e.updatedAt AS updatedAt
	`
	params := map[string]interface{}{"uuid": essayUUID}

	result, err := neo4j.ExecuteQuery(context.Background(), h.db.Driver, query, params, neo4j.EagerResultTransformer)
	if err != nil {
		log.Printf("Database error fetching essay: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch essay"})
		return
	}

	if len(result.Records) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Essay not found"})
		return
	}

	record := result.Records[0]
	essay := models.EssayResponse{}
	if uuid, ok := record.Get("uuid"); ok {
		essay.UUID = uuid.(string)
	}
	if title, ok := record.Get("title"); ok {
		essay.Title = title.(string)
	}
	if content, ok := record.Get("content"); ok {
		essay.Content = content.(string)
	}
	if createdAt, ok := record.Get("createdAt"); ok {
		essay.CreatedAt = createdAt.(time.Time)
	}
	if updatedAt, ok := record.Get("updatedAt"); ok {
		essay.UpdatedAt = updatedAt.(time.Time)
	}

	c.JSON(http.StatusOK, essay)
}

// ListEssays retrieves all essays for the authenticated user
func (h *Handler) ListEssays(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	query := `
		MATCH (u:User {username: $username})-[:AUTHORED]->(e:Essay)
		RETURN e.uuid AS uuid, e.title AS title, e.content AS content,
		       e.createdAt AS createdAt, e.updatedAt AS updatedAt
		ORDER BY e.createdAt DESC
	`
	params := map[string]interface{}{"username": username.(string)}

	result, err := neo4j.ExecuteQuery(context.Background(), h.db.Driver, query, params, neo4j.EagerResultTransformer)
	if err != nil {
		log.Printf("Database error listing essays: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list essays"})
		return
	}

	essays := []models.EssayResponse{}
	for _, record := range result.Records {
		essay := models.EssayResponse{}
		if uuid, ok := record.Get("uuid"); ok {
			essay.UUID = uuid.(string)
		}
		if title, ok := record.Get("title"); ok {
			essay.Title = title.(string)
		}
		if content, ok := record.Get("content"); ok {
			essay.Content = content.(string)
		}
		if createdAt, ok := record.Get("createdAt"); ok {
			essay.CreatedAt = createdAt.(time.Time)
		}
		if updatedAt, ok := record.Get("updatedAt"); ok {
			essay.UpdatedAt = updatedAt.(time.Time)
		}
		essays = append(essays, essay)
	}

	c.JSON(http.StatusOK, essays)
}

// UpdateEssay updates an existing essay
func (h *Handler) UpdateEssay(c *gin.Context) {
	essayUUID := c.Param("uuid")
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req models.UpdateEssayRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Validate that at least one field is being updated
	if req.Title == "" && req.Content == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "At least one field (title or content) must be provided for update"})
		return
	}

	// Build dynamic SET clause
	setClauses := []string{"e.updatedAt = datetime()"}
	params := map[string]interface{}{
		"uuid":     essayUUID,
		"username": username.(string),
	}

	if req.Title != "" {
		setClauses = append(setClauses, "e.title = $title")
		params["title"] = req.Title
	}
	if req.Content != "" {
		setClauses = append(setClauses, "e.content = $content")
		params["content"] = req.Content
	}

	query := fmt.Sprintf(`
		MATCH (u:User {username: $username})-[:AUTHORED]->(e:Essay {uuid: $uuid})
		SET %s
		RETURN e.uuid AS uuid, e.title AS title, e.content AS content,
		       e.createdAt AS createdAt, e.updatedAt AS updatedAt
	`, strings.Join(setClauses, ", "))

	result, err := neo4j.ExecuteQuery(context.Background(), h.db.Driver, query, params, neo4j.EagerResultTransformer)
	if err != nil {
		log.Printf("Database error updating essay: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update essay"})
		return
	}

	if len(result.Records) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Essay not found or you don't have permission"})
		return
	}

	record := result.Records[0]
	essay := models.EssayResponse{}
	if uuid, ok := record.Get("uuid"); ok {
		essay.UUID = uuid.(string)
	}
	if title, ok := record.Get("title"); ok {
		essay.Title = title.(string)
	}
	if content, ok := record.Get("content"); ok {
		essay.Content = content.(string)
	}
	if createdAt, ok := record.Get("createdAt"); ok {
		essay.CreatedAt = createdAt.(time.Time)
	}
	if updatedAt, ok := record.Get("updatedAt"); ok {
		essay.UpdatedAt = updatedAt.(time.Time)
	}

	c.JSON(http.StatusOK, essay)
}

// DeleteEssay deletes an essay
func (h *Handler) DeleteEssay(c *gin.Context) {
	essayUUID := c.Param("uuid")
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	query := `
		MATCH (u:User {username: $username})-[r:AUTHORED]->(e:Essay {uuid: $uuid})
		DELETE r, e
		RETURN count(e) AS deleted
	`
	params := map[string]interface{}{
		"uuid":     essayUUID,
		"username": username.(string),
	}

	result, err := neo4j.ExecuteQuery(context.Background(), h.db.Driver, query, params, neo4j.EagerResultTransformer)
	if err != nil {
		log.Printf("Database error deleting essay: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete essay"})
		return
	}

	if len(result.Records) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Essay not found or you don't have permission"})
		return
	}

	record := result.Records[0]
	if deleted, ok := record.Get("deleted"); ok && deleted.(int64) > 0 {
		c.JSON(http.StatusOK, gin.H{"message": "Essay deleted successfully"})
	} else {
		c.JSON(http.StatusNotFound, gin.H{"error": "Essay not found or you don't have permission"})
	}
}