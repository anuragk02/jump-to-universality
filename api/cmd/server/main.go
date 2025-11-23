package main

import (
	"context"
	"log"
	"os"

	"api/internal/database"
	"api/internal/handlers"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	db := database.NewDB()
	defer db.Close(context.Background())

	h := handlers.NewHandler(db)
	r := gin.Default()

	// CORS configuration
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173"},
		AllowMethods:     []string{"POST", "GET", "OPTIONS", "PUT", "DELETE"},
		AllowHeaders:     []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	}))

	// Public routes
	r.GET("/health", h.HealthCheck)
	r.POST("/login", h.LoginHandler)

	// Protected routes (require authentication)
	protected := r.Group("/api")
	protected.Use(handlers.AuthMiddleware())
	{
		// User routes
		protected.GET("/profile", h.GetProfile)

		// Essay routes
		protected.POST("/essays", h.CreateEssay)
		protected.GET("/essays", h.ListEssays)
		protected.GET("/essays/:uuid", h.GetEssay)
		protected.PUT("/essays/:uuid", h.UpdateEssay)
		protected.DELETE("/essays/:uuid", h.DeleteEssay)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on port %s", port)
	r.Run(":" + port)
}