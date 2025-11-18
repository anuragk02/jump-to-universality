package main

import (
	"context"
	"log"
	"os"

	"api/internal/database"
	"api/internal/handlers"

	"github.com/gin-gonic/gin"
)

func main() {
	db := database.NewDB()
	defer db.Close(context.Background())

	h := handlers.NewHandler(db)
	r := gin.Default()

	// Public routes
	r.GET("/health", h.HealthCheck)
	r.POST("/api/login", h.LoginHandler)

	// Protected routes (require authentication)
	protected := r.Group("/api")
	protected.Use(handlers.AuthMiddleware())
	{
		// Add your protected routes here
		protected.GET("/profile", h.GetProfile)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on port %s", port)
	r.Run(":" + port)
}