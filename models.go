package api_pkg

import (
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// Custom errors
var (
    ErrUserNotFound      = errors.New("user not found")
    ErrAccountNotFound   = errors.New("account not found")
    ErrInsufficientFunds = errors.New("insufficient funds")
    ErrInvalidInput     = errors.New("invalid input")
    ErrUnauthorized     = errors.New("unauthorized access")
    ErrDuplicateUser    = errors.New("username already exists")
)

// Claims represents JWT claims structure
type Claims struct {
    Username string `json:"username"`
    Role     string `json:"role"`
    jwt.StandardClaims
}

// User represents the user model
type User struct {
    ID       int    `json:"id"`
    Username string `json:"username"`
    Password string `json:"-"` // Never send password in JSON response
    Role     string `json:"role"` // "admin" or "user"
    CreatedAt time.Time `json:"created_at"`
}

// Account represents the account model
type Account struct {
    ID        int       `json:"id"`
    UserID    int       `json:"user_id"`
    Balance   float64   `json:"balance"`
    CreatedAt time.Time `json:"created_at"`
}

// UserResponse represents the user data that's safe to send in responses
type UserResponse struct {
    ID        int       `json:"id"`
    Username  string    `json:"username"`
    Role      string    `json:"role"`
    CreatedAt time.Time `json:"created_at"`
}

// ToResponse converts User to UserResponse
func (u *User) ToResponse() UserResponse {
    return UserResponse{
        ID:        u.ID,
        Username:  u.Username,
        Role:      u.Role,
        CreatedAt: u.CreatedAt,
    }
}

// Constants for validation
const (
    MinPasswordLength = 8
    MaxPasswordLength = 72 // bcrypt max length
    MaxUsernameLength = 50
)

// Available roles
const (
    RoleUser  = "user"
    RoleAdmin = "admin"
)