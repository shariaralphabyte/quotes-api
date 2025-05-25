package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"golang.org/x/crypto/bcrypt"
	_ "github.com/mattn/go-sqlite3"
)

// Models
type User struct {
	ID        int       `json:"id"`
	Email     string    `json:"email"`
	Password  string    `json:"-"`
	Role      string    `json:"role"`
	APIKey    string    `json:"api_key,omitempty"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
}

type Quote struct {
	ID        int       `json:"id"`
	Quote     string    `json:"quote"`
	Author    string    `json:"author"`
	UserID    int       `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
}

type AuditLog struct {
	ID        int       `json:"id"`
	UserID    int       `json:"user_id"`
	Action    string    `json:"action"`
	Details   string    `json:"details"`
	Timestamp time.Time `json:"timestamp"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type QuoteRequest struct {
	Quote  string `json:"quote"`
	Author string `json:"author"`
}

type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Database
var db *sql.DB

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./quotes.db")
	if err != nil {
		log.Fatal("Error opening database:", err)
	}

	// Create tables
	createTables()
	
	// Create default admin user
	createDefaultAdmin()
}

func createTables() {
	// Users table
	userTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		role TEXT NOT NULL DEFAULT 'user',
		api_key TEXT UNIQUE,
		is_active BOOLEAN DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	// Quotes table
	quoteTable := `
	CREATE TABLE IF NOT EXISTS quotes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		quote TEXT NOT NULL,
		author TEXT NOT NULL,
		user_id INTEGER,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users (id)
	);`

	// Audit logs table
	auditTable := `
	CREATE TABLE IF NOT EXISTS audit_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER,
		action TEXT NOT NULL,
		details TEXT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users (id)
	);`

	tables := []string{userTable, quoteTable, auditTable}
	for _, table := range tables {
		if _, err := db.Exec(table); err != nil {
			log.Fatal("Error creating table:", err)
		}
	}
}

func createDefaultAdmin() {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE role = 'admin'").Scan(&count)
	if err != nil {
		log.Fatal("Error checking admin user:", err)
	}

	if count == 0 {
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("Alpha1234"), bcrypt.DefaultCost)
		apiKey := generateAPIKey()
		
		_, err := db.Exec(`
			INSERT INTO users (email, password, role, api_key, is_active) 
			VALUES (?, ?, 'admin', ?, 1)`,
			"Shariar@gmail.com", string(hashedPassword), apiKey)
		
		if err != nil {
			log.Fatal("Error creating default admin:", err)
		}
		
		log.Println("Default admin created - Email: Shariar@gmail.com, Password: Alpha1234")
	}
}

// Utility functions
func generateAPIKey() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func logAudit(userID int, action, details string) {
	_, err := db.Exec(`
		INSERT INTO audit_logs (user_id, action, details) 
		VALUES (?, ?, ?)`, userID, action, details)
	if err != nil {
		log.Printf("Error logging audit: %v", err)
	}
}

func respondJSON(w http.ResponseWriter, success bool, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	response := Response{
		Success: success,
		Message: message,
		Data:    data,
	}
	json.NewEncoder(w).Encode(response)
}

func respondError(w http.ResponseWriter, statusCode int, message string) {
	w.WriteHeader(statusCode)
	respondJSON(w, false, message, nil)
}

// Middleware
func authenticateAPIKey(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			respondError(w, http.StatusUnauthorized, "API key required")
			return
		}

		var user User
		err := db.QueryRow(`
			SELECT id, email, role, is_active 
			FROM users WHERE api_key = ?`, apiKey).Scan(
			&user.ID, &user.Email, &user.Role, &user.IsActive)

		if err != nil {
			respondError(w, http.StatusUnauthorized, "Invalid API key")
			return
		}

		if !user.IsActive {
			respondError(w, http.StatusForbidden, "Account deactivated")
			return
		}

		// Add user to request context
		r.Header.Set("User-ID", strconv.Itoa(user.ID))
		r.Header.Set("User-Role", user.Role)
		next(w, r)
	}
}

func requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return authenticateAPIKey(func(w http.ResponseWriter, r *http.Request) {
		role := r.Header.Get("User-Role")
		if role != "admin" {
			respondError(w, http.StatusForbidden, "Admin access required")
			return
		}
		next(w, r)
	})
}

// Handlers
func healthCheck(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, true, "API is healthy", map[string]string{
		"status": "running",
		"time":   time.Now().Format(time.RFC3339),
	})
}

func adminLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	var user User
	err := db.QueryRow(`
		SELECT id, email, password, role, api_key, is_active 
		FROM users WHERE email = ? AND role = 'admin'`, req.Email).Scan(
		&user.ID, &user.Email, &user.Password, &user.Role, &user.APIKey, &user.IsActive)

	if err != nil {
		respondError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	if !checkPassword(req.Password, user.Password) {
		respondError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	if !user.IsActive {
		respondError(w, http.StatusForbidden, "Account deactivated")
		return
	}

	logAudit(user.ID, "LOGIN", "Admin login successful")
	
	user.Password = ""
	respondJSON(w, true, "Login successful", user)
}

func registerUser(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		respondError(w, http.StatusBadRequest, "Email and password required")
		return
	}

	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Error processing password")
		return
	}

	apiKey := generateAPIKey()

	result, err := db.Exec(`
		INSERT INTO users (email, password, role, api_key, is_active) 
		VALUES (?, ?, 'user', ?, 1)`,
		req.Email, hashedPassword, apiKey)

	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			respondError(w, http.StatusConflict, "Email already exists")
			return
		}
		respondError(w, http.StatusInternalServerError, "Error creating user")
		return
	}

	userID, _ := result.LastInsertId()
	logAudit(int(userID), "REGISTER", "User registered successfully")

	respondJSON(w, true, "User registered successfully", map[string]string{
		"api_key": apiKey,
		"email":   req.Email,
	})
}

func addQuote(w http.ResponseWriter, r *http.Request) {
	var req QuoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Quote == "" || req.Author == "" {
		respondError(w, http.StatusBadRequest, "Quote and author required")
		return
	}

	userID, _ := strconv.Atoi(r.Header.Get("User-ID"))

	result, err := db.Exec(`
		INSERT INTO quotes (quote, author, user_id) 
		VALUES (?, ?, ?)`, req.Quote, req.Author, userID)

	if err != nil {
		respondError(w, http.StatusInternalServerError, "Error adding quote")
		return
	}

	quoteID, _ := result.LastInsertId()
	logAudit(userID, "ADD_QUOTE", fmt.Sprintf("Added quote ID: %d", quoteID))

	respondJSON(w, true, "Quote added successfully", map[string]int64{
		"quote_id": quoteID,
	})
}

func getQuote(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid quote ID")
		return
	}

	var quote Quote
	err = db.QueryRow(`
		SELECT id, quote, author, user_id, created_at 
		FROM quotes WHERE id = ?`, id).Scan(
		&quote.ID, &quote.Quote, &quote.Author, &quote.UserID, &quote.CreatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			respondError(w, http.StatusNotFound, "Quote not found")
			return
		}
		respondError(w, http.StatusInternalServerError, "Error fetching quote")
		return
	}

	respondJSON(w, true, "Quote retrieved successfully", quote)
}

func getAllQuotes(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
		SELECT id, quote, author, user_id, created_at 
		FROM quotes ORDER BY created_at DESC`)

	if err != nil {
		respondError(w, http.StatusInternalServerError, "Error fetching quotes")
		return
	}
	defer rows.Close()

	var quotes []Quote
	for rows.Next() {
		var quote Quote
		err := rows.Scan(&quote.ID, &quote.Quote, &quote.Author, &quote.UserID, &quote.CreatedAt)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "Error processing quotes")
			return
		}
		quotes = append(quotes, quote)
	}

	respondJSON(w, true, "Quotes retrieved successfully", quotes)
}

func getAllUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
		SELECT id, email, role, api_key, is_active, created_at 
		FROM users ORDER BY created_at DESC`)

	if err != nil {
		respondError(w, http.StatusInternalServerError, "Error fetching users")
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Email, &user.Role, &user.APIKey, &user.IsActive, &user.CreatedAt)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "Error processing users")
			return
		}
		users = append(users, user)
	}

	respondJSON(w, true, "Users retrieved successfully", users)
}

func deactivateUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	adminID, _ := strconv.Atoi(r.Header.Get("User-ID"))

	_, err = db.Exec("UPDATE users SET is_active = 0 WHERE id = ? AND role != 'admin'", userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Error deactivating user")
		return
	}

	logAudit(adminID, "DEACTIVATE_USER", fmt.Sprintf("Deactivated user ID: %d", userID))
	respondJSON(w, true, "User deactivated successfully", nil)
}

func reactivateUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	adminID, _ := strconv.Atoi(r.Header.Get("User-ID"))

	_, err = db.Exec("UPDATE users SET is_active = 1 WHERE id = ?", userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Error reactivating user")
		return
	}

	logAudit(adminID, "REACTIVATE_USER", fmt.Sprintf("Reactivated user ID: %d", userID))
	respondJSON(w, true, "User reactivated successfully", nil)
}

func getAuditLogs(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
		SELECT al.id, al.user_id, u.email, al.action, al.details, al.timestamp 
		FROM audit_logs al 
		LEFT JOIN users u ON al.user_id = u.id 
		ORDER BY al.timestamp DESC`)

	if err != nil {
		respondError(w, http.StatusInternalServerError, "Error fetching audit logs")
		return
	}
	defer rows.Close()

	var logs []map[string]interface{}
	for rows.Next() {
		var log AuditLog
		var email sql.NullString
		err := rows.Scan(&log.ID, &log.UserID, &email, &log.Action, &log.Details, &log.Timestamp)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "Error processing audit logs")
			return
		}

		logEntry := map[string]interface{}{
			"id":        log.ID,
			"user_id":   log.UserID,
			"email":     email.String,
			"action":    log.Action,
			"details":   log.Details,
			"timestamp": log.Timestamp,
		}
		logs = append(logs, logEntry)
	}

	respondJSON(w, true, "Audit logs retrieved successfully", logs)
}

func main() {
	// Initialize database
	initDB()
	defer db.Close()

	// Setup routes
	r := mux.NewRouter()
	
	// Public routes
	r.HandleFunc("/health", healthCheck).Methods("GET")
	r.HandleFunc("/admin/login", adminLogin).Methods("POST")
	r.HandleFunc("/register", registerUser).Methods("POST")
	r.HandleFunc("/quotes", getAllQuotes).Methods("GET")
	r.HandleFunc("/quotes/{id}", getQuote).Methods("GET")

	// User routes (require API key)
	r.HandleFunc("/quotes", authenticateAPIKey(addQuote)).Methods("POST")

	// Admin routes (require admin API key)
	r.HandleFunc("/admin/users", requireAdmin(getAllUsers)).Methods("GET")
	r.HandleFunc("/admin/users/{id}/deactivate", requireAdmin(deactivateUser)).Methods("PUT")
	r.HandleFunc("/admin/users/{id}/reactivate", requireAdmin(reactivateUser)).Methods("PUT")
	r.HandleFunc("/admin/audit-logs", requireAdmin(getAuditLogs)).Methods("GET")

	// Setup CORS
	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"*"},
	})

	handler := c.Handler(r)

	// Start server
	port := ":8080"
	log.Printf("Server starting on port %s", port)
	log.Printf("Default Admin - Email: Shariar@gmail.com, Password: Alpha1234")
	
	if err := http.ListenAndServe(port, handler); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}