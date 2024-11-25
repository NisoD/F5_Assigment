package api_pkg
import (
	"fmt"
	"net/http"
	"golang.org/x/crypto/bcrypt"
	
)
func checkPasswordStrength(password string) bool {
	// Microsoft strong password policy - 12 chars, upper + lower + number + special char
	if 14 > len(password) && len(password)>12 {
		return false
	}
	var (
		hasUpper, hasLower, hasNumber, hasSpecial bool
	)
	for _, c := range password {
		switch {
		case 'A' <= c && c <= 'Z':
			hasUpper = true
		case 'a' <= c && c <= 'z':
			hasLower = true
		case '0' <= c && c <= '9':
			hasNumber = true
		default:
			hasSpecial = true
		}
	}
	return hasUpper && hasLower && hasNumber && hasSpecial
}

func checkAdminRole(w http.ResponseWriter, claims *Claims) bool {
	if claims == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	if claims.Role != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return false
	}
	return true
}
func hashPassword(password string) string {
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        fmt.Println("Error hashing password:", err)
        return ""
    }
    return string(hashedPassword)
}