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
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"github.com/gin-gonic/gin"
	// "github.com/google/uuid"
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
	// This query IS case-sensitive.
	query := `MATCH (u:User {username: $username}) 
              RETURN u.uuid, u.username, u.password`
	params := map[string]interface{}{"username": req.Username}

	// ----
	// OPTIONAL: If you want case-INSENSITIVE login, use this query instead:
	// query := `MATCH (u:User) 
	//           WHERE toLower(u.username) = toLower($username)
	//           RETURN u.uuid, u.username, u.password`
	// ----

	records, err := h.db.ExecuteRead(context.Background(), query, params)
	if err != nil {
		log.Printf("Database query error in LoginHandler: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	// 3. Check if user was found
	if len(records) == 0 {
		// --- DEBUGGING: This is Failure Point 1 ---
		// This means the query returned 0 rows.
		// The username in your DB does not match what was sent.
		log.Printf("Login failed: User '%s' not found.", req.Username)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// 4. Populate user from database record
	record := records[0]
	user.Username, _ = record["u.username"].(string)
	user.Password, _ = record["u.password"].(string)

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
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}