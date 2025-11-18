package models

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type User struct {
	Username string    `json:"username"`
	Password string    `json:"password"` // Hashed password
}
