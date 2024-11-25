package api_pkg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

// Thread-safe storage
var (
    idCounter int64 = 0
    users     = make(map[string]User)
    accounts  = make(map[int]Account) // Changed to map for O(1) lookup
    mu        sync.RWMutex
)

// JWT configuration
var (
    jwtKey        = []byte(os.Getenv("JWT_SECRET_KEY"))
    jwtExpiration = 24 * time.Hour
)

// generateID generates a unique ID thread-safely
func generateID() int {
    return int(atomic.AddInt64(&idCounter, 1))
}

// Initialize test data
func InitializeTestData() {
    mu.Lock()
    defer mu.Unlock()

    // Clear existing data
    users = make(map[string]User)
    accounts = make(map[int]Account)

    // Create test users with properly hashed passwords
    testUsers := []struct {
        username, password, role string
    }{
        {"user1", "Password@123", RoleUser},
        {"user2", "Password@456", RoleUser},
        {"admin", "Admin@123", RoleAdmin},
    }

    for _, u := range testUsers {
        hashedPass, err := bcrypt.GenerateFromPassword([]byte(u.password), bcrypt.DefaultCost)
        if err != nil {
            panic(fmt.Sprintf("Failed to hash password for %s: %v", u.username, err))
        }

        user := User{
            ID:        generateID(),
            Username:  u.username,
            Password:  string(hashedPass),
            Role:      u.role,
            CreatedAt: time.Now(),
        }
        users[u.username] = user

        // Create account for each user
        account := Account{
            ID:        generateID(),
            UserID:    user.ID,
            Balance:   1000.0, // Initial balance
            CreatedAt: time.Now(),
        }
        accounts[account.ID] = account
    }

    fmt.Println("Test data initialized successfully")
}

// validatePassword checks if the password meets security requirements
func validatePassword(password string) error {
    if len(password) < MinPasswordLength || len(password) > MaxPasswordLength {
        return fmt.Errorf("password length must be between %d and %d characters", MinPasswordLength, MaxPasswordLength)
    }
    
    var (
        hasUpper   bool
        hasLower   bool
        hasNumber  bool
        hasSpecial bool
    )
    
    for _, char := range password {
        switch {
        case 'A' <= char && char <= 'Z':
            hasUpper = true
        case 'a' <= char && char <= 'z':
            hasLower = true
        case '0' <= char && char <= '9':
            hasNumber = true
        case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?", char):
            hasSpecial = true
        }
    }
    
    if !(hasUpper && hasLower && hasNumber && hasSpecial) {
        return errors.New("password must contain at least one uppercase letter, one lowercase letter, one number, and one special character")
    }
    
    return nil
}

// Register handles user registration
func Register(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    var input struct {
        Username string `json:"username"`
        Password string `json:"password"`
        Role     string `json:"role"`
    }

    if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Validate input
    if len(input.Username) == 0 || len(input.Username) > MaxUsernameLength {
        http.Error(w, "Invalid username length", http.StatusBadRequest)
        return
    }

    if err := validatePassword(input.Password); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    // Only allow user role for registration
    if input.Role != RoleUser {
        http.Error(w, "Invalid role", http.StatusBadRequest)
        return
    }

    mu.Lock()
    defer mu.Unlock()

    // Check for existing user
    if _, exists := users[input.Username]; exists {
        http.Error(w, ErrDuplicateUser.Error(), http.StatusConflict)
        return
    }

    // Hash password
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
    if err != nil {
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    // Create user
    user := User{
        ID:        generateID(),
        Username:  input.Username,
        Password:  string(hashedPassword),
        Role:      input.Role,
        CreatedAt: time.Now(),
    }
    users[user.Username] = user

    // Create response
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(user.ToResponse())
}
// Login handles user authentication
func Login(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    var input struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }

    if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    mu.RLock()
    user, exists := users[input.Username]
    mu.RUnlock()

    if !exists {
        // Use same error message for non-existent user and wrong password
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    // Create token
    expirationTime := time.Now().Add(jwtExpiration)
    claims := &Claims{
        Username: user.Username,
        Role:     user.Role,
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: expirationTime.Unix(),
            IssuedAt:  time.Now().Unix(),
            Issuer:    "api_service",
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(jwtKey)
    if err != nil {
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    // Return token
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "token": tokenString,
        "type":  "Bearer",
    })
}

// AccountsHandler handles account-related operations
func AccountsHandler(w http.ResponseWriter, r *http.Request) {
    claims, ok := r.Context().Value("claims").(*Claims)
    if !ok || claims.Role != RoleAdmin {
        http.Error(w, "Unauthorized", http.StatusForbidden)
        return
    }

    switch r.Method {
    case http.MethodPost:
        createAccount(w, r)
    case http.MethodGet:
        listAccounts(w, r)
    default:
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
    }
}

func createAccount(w http.ResponseWriter, r *http.Request) {
    // check for Admin


	var input struct {
        UserID  int     `json:"user_id"`
        Balance float64 `json:"balance"`
    }

    if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    if input.Balance < 0 {
        http.Error(w, "Initial balance cannot be negative", http.StatusBadRequest)
        return
    }

    mu.Lock()
    defer mu.Unlock()

    // Verify user exists
    userExists := false
    for _, user := range users {
        if user.ID == input.UserID {
            userExists = true
            break
        }
    }

    if !userExists {
        http.Error(w, ErrUserNotFound.Error(), http.StatusNotFound)
        return
    }

    account := Account{
        ID:        generateID(),
        UserID:    input.UserID,
        Balance:   input.Balance,
        CreatedAt: time.Now(),
    }

    accounts[account.ID] = account

    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(account)
}

func listAccounts(w http.ResponseWriter, r *http.Request) {
    mu.RLock()
    accountsList := make([]Account, 0, len(accounts))
    for _, acc := range accounts {
        accountsList = append(accountsList, acc)
    }
    mu.RUnlock()

    json.NewEncoder(w).Encode(accountsList)
}
func BalanceHandler(w http.ResponseWriter, r *http.Request) {
    claims, ok := r.Context().Value("claims").(*Claims)
    if !ok {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    userIDStr := r.URL.Query().Get("user_id")
    userID, err := strconv.Atoi(userIDStr)
    if err != nil {
        http.Error(w, "Invalid user_id", http.StatusBadRequest)
        return
    }

    mu.RLock()
    currentUser, exists := users[claims.Username]
    mu.RUnlock()

    if !exists {
        http.Error(w, "User not found", http.StatusForbidden)
        return
    }

    // Only allow if admin or accessing own account
    if claims.Role != RoleAdmin && currentUser.ID != userID {
        http.Error(w, "Unauthorized access", http.StatusForbidden)
        return
    }

    switch r.Method {
    case http.MethodGet:
        getBalance(w, r, userID)
    case http.MethodPost:
        depositBalance(w, r, claims)
    case http.MethodDelete:
        withdrawBalance(w, r, claims)
    default:
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
    }
}

func depositBalance(w http.ResponseWriter, r *http.Request, claims *Claims) {
    var input struct {
        UserID int     `json:"user_id"`
        Amount float64 `json:"amount"`
    }

    if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }
    

    // Validate input
    if input.Amount <= 0 {
        http.Error(w, "Amount must be positive", http.StatusBadRequest)
        return
    }

    // Check for unreasonably large deposits that might indicate an attack
    if input.Amount > 1000000 {
        http.Error(w, "Amount exceeds maximum allowed deposit", http.StatusBadRequest)
        return
    }

    if !checkBalanceAccess(claims, input.UserID) {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }

    mu.Lock()
    defer mu.Unlock()

    // Find the account
    var account *Account
    for id, acc := range accounts {
        if acc.UserID == input.UserID {
            accCopy := acc
            account = &accCopy
            account.ID = id
            break
        }
    }

    if account == nil {
        http.Error(w, ErrAccountNotFound.Error(), http.StatusNotFound)
        return
    }

    // Update balance with overflow check
    newBalance := account.Balance + input.Amount
    if newBalance < account.Balance { // Check for overflow
        http.Error(w, "Invalid transaction: amount too large", http.StatusBadRequest)
        return
    }

    account.Balance = newBalance
    accounts[account.ID] = *account

    // Return updated account
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(account)
}

func getBalance(w http.ResponseWriter, r *http.Request, userID int) {
    mu.RLock()
    var userAccount *Account
    for _, acc := range accounts {
        if acc.UserID == userID {
            accCopy := acc
            userAccount = &accCopy
            break
        }
    }
    mu.RUnlock()

    if userAccount == nil {
        http.Error(w, ErrAccountNotFound.Error(), http.StatusNotFound)
        return
    }

    json.NewEncoder(w).Encode(map[string]float64{
        "balance": userAccount.Balance,
    })
}

func checkBalanceAccess(claims *Claims, targetUserID int) bool {
    if claims.Role == RoleAdmin {
        return true
    }

    mu.RLock()
    user, exists := users[claims.Username]
    mu.RUnlock()

    return exists && user.ID == targetUserID
}



func withdrawBalance(w http.ResponseWriter, r *http.Request, claims *Claims) {
    var input struct {
        UserID int     `json:"user_id"`
        Amount float64 `json:"amount"`
    }

    if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Validate input
    if input.Amount <= 0 {
        http.Error(w, "Amount must be positive", http.StatusBadRequest)
        return
    }

    if !checkBalanceAccess(claims, input.UserID) {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }

    mu.Lock()
    defer mu.Unlock()

    // Find the account
    var account *Account
    for id, acc := range accounts {
        if acc.UserID == input.UserID {
            accCopy := acc
            account = &accCopy
            account.ID = id
            break
        }
    }

    if account == nil {
        http.Error(w, ErrAccountNotFound.Error(), http.StatusNotFound)
        return
    }

    // Check sufficient funds
    if account.Balance < input.Amount {
        http.Error(w, ErrInsufficientFunds.Error(), http.StatusBadRequest)
        return
    }

    // Update balance
    account.Balance -= input.Amount
    accounts[account.ID] = *account

    // Return updated account
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(account)
}

// Auth middleware for JWT verification
// Auth handles user authentication and access control
func Auth(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Validate authorization header
        token, err := extractAndValidateToken(r)
        if err != nil {
            http.Error(w, err.Error(), http.StatusUnauthorized)
            return
        }

        // Add claims to context and continue
        ctx := context.WithValue(r.Context(), "claims", token.Claims.(*Claims))
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

// extractAndValidateToken validates the JWT token from the request
func extractAndValidateToken(r *http.Request) (*jwt.Token, error) {
    // Extract token from Authorization header
    tokenStr, err := extractTokenFromHeader(r)
    if err != nil {
        return nil, err
    }

    // Parse and validate token
    return parseToken(tokenStr)
}

// extractTokenFromHeader retrieves the JWT token from the Authorization header
func extractTokenFromHeader(r *http.Request) (string, error) {
    authHeader := r.Header.Get("Authorization")
    if authHeader == "" {
        return "", errors.New("missing authorization header")
    }

    parts := strings.Split(authHeader, " ")
    if len(parts) != 2 || parts[0] != "Bearer" {
        return "", errors.New("invalid authorization header format")
    }

    return parts[1], nil
}

// parseToken validates the JWT token's signature and claims
func parseToken(tokenStr string) (*jwt.Token, error) {
    claims := &Claims{}
    token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
        // Validate signing method
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return jwtKey, nil
    })

    if err != nil {
        return nil, errors.New("invalid token")
    }

    if !token.Valid {
        return nil, errors.New("token is invalid")
    }

    // Check token expiration
    if time.Now().Unix() > claims.ExpiresAt {
        return nil, errors.New("token has expired")
    }

    return token, nil
}
