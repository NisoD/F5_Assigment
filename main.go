package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/justinas/alice"
	"golang.org/x/time/rate"

	"f5.com/ha/api_pkg"
)

// Configuration constants
const (
    defaultPort         = "8080"
    shutdownTimeout     = 30 * time.Second
    readTimeout        = 5 * time.Second
    writeTimeout       = 10 * time.Second
    idleTimeout        = 120 * time.Second
    maxRequestSize     = 1 << 20 // 1 MB
    logFilePermissions = 0644
)

// Global logger
var (
    errorLog *log.Logger
    accessLog *log.Logger
    logFile *os.File
)

func init() {
    // Initialize error logging
    errorLog = log.New(os.Stderr, "ERROR\t", log.Ldate|log.Ltime|log.Lshortfile)

    // Initialize access logging
    err := setupLogging()
    if err != nil {
        errorLog.Fatal(err)
    }
}

func setupLogging() error {
    // Create logs directory if it doesn't exist
    err := os.MkdirAll("logs", 0755)
    if err != nil {
        return err
    }

    // Open log file with timestamp in name
    timestamp := time.Now().Format("2006-01-02")
    logPath := filepath.Join("logs", fmt.Sprintf("access-%s.log", timestamp))
    
    logFile, err = os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, logFilePermissions)
    if err != nil {
        return err
    }

    accessLog = log.New(logFile, "", 0)
    return nil
}

func main() {
    // Load environment variables
    port := os.Getenv("PORT")
    if port == "" {
        port = defaultPort
    }

    // Initialize test data
    api_pkg.InitializeTestData()

    // Create router and add routes
    router := http.NewServeMux()

    // Middleware chains
    baseChain := alice.New(
        securityHeadersMiddleware,
        rateLimitMiddleware,
        requestSizeMiddleware(maxRequestSize),
        recoveryMiddleware,
        accessLogMiddleware,
    )
    // Public routes
    publicChain := baseChain.ThenFunc(api_pkg.Register)
    router.Handle("/register", publicChain)

    publicChain = baseChain.ThenFunc(api_pkg.Login)
    router.Handle("/login", publicChain)


    // Protected routes
    protectedChain := baseChain.Append(api_pkg.Auth).ThenFunc(api_pkg.AccountsHandler)
    router.Handle("/accounts", protectedChain)

    protectedChain = baseChain.Append(api_pkg.Auth).ThenFunc(api_pkg.BalanceHandler)
    router.Handle("/balance", protectedChain)


    // Create server
    srv := &http.Server{
        Addr:         ":" + port,
        Handler:      router,
        ErrorLog:     errorLog,
        ReadTimeout:  readTimeout,
        WriteTimeout: writeTimeout,
        IdleTimeout:  idleTimeout,
    }

    // Start server
    go func() {
        log.Printf("Starting server on port %s...\n", port)
        if err := srv.ListenAndServe(); err != http.ErrServerClosed {
            errorLog.Fatal(err)
        }
    }()

    // Graceful shutdown
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    log.Println("Server is shutting down...")

    ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
    defer cancel()

    if err := srv.Shutdown(ctx); err != nil {
        errorLog.Printf("Server forced to shutdown: %v\n", err)
    }

    if err := logFile.Close(); err != nil {
        errorLog.Printf("Error closing log file: %v\n", err)
    }

    log.Println("Server stopped")
}

// Middleware implementations
func securityHeadersMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Security headers
        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("X-Frame-Options", "DENY")
        w.Header().Set("X-XSS-Protection", "1; mode=block")
        w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        w.Header().Set("Content-Security-Policy", "default-src 'self'")
        w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
        w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

        next.ServeHTTP(w, r)
    })
}

// Custom response writer that tracks response size and status code
type responseWriter struct {
    http.ResponseWriter
    status int
    size   int
}

func (rw *responseWriter) WriteHeader(status int) {
    rw.status = status
    rw.ResponseWriter.WriteHeader(status)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
    size, err := rw.ResponseWriter.Write(b)
    rw.size += size
    return size, err
}

// Rate limiting middleware
func rateLimitMiddleware(next http.Handler) http.Handler {
    limiter := rate.NewLimiter(rate.Every(time.Second), 10) // 10 requests per second
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if !limiter.Allow() {
            http.Error(w, "Too many requests", http.StatusTooManyRequests)
            return
        }
        next.ServeHTTP(w, r)
    })
}

// Request size limiting middleware
func requestSizeMiddleware(maxSize int64) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            r.Body = http.MaxBytesReader(w, r.Body, maxSize)
            next.ServeHTTP(w, r)
        })
    }
}

// Recovery middleware
func recoveryMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        defer func() {
            if err := recover(); err != nil {
                errorLog.Printf("panic: %v", err)
                http.Error(w, "Internal Server Error", http.StatusInternalServerError)
            }
        }()
        next.ServeHTTP(w, r)
    })
}

// Access logging middleware
func accessLogMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()

        // Create custom response writer to capture status and size
        rw := &responseWriter{
            ResponseWriter: w,
            status:        http.StatusOK,
        }

        // Process request
        next.ServeHTTP(rw, r)

        // Prepare log entry
        entry := LogEntry{
            Timestamp: time.Now().Format(time.RFC3339),
            Request: RequestLog{
                Method:     r.Method,
                URL:        r.URL.String(),
                Headers:    sanitizeHeaders(r.Header),
                QueryParams: sanitizeQueryParams(r.URL.Query()),
                BodySize:   r.ContentLength,
            },
            Response: ResponseLog{
                Status:      rw.status,
                StatusClass: fmt.Sprintf("%dxx", rw.status/100),
                Size:        int64(rw.size),
            },
            Duration: time.Since(start).Milliseconds(),
        }

        // Log entry
        if err := logEntry(entry); err != nil {
            errorLog.Printf("Failed to log access: %v", err)
        }
    })
}

// Logging types and functions
type LogEntry struct {
    Timestamp string      `json:"timestamp"`
    Request   RequestLog  `json:"req"`
    Response  ResponseLog `json:"rsp"`
    Duration  int64      `json:"duration_ms"`
}

type RequestLog struct {
    Method      string      `json:"method"`
    URL         string      `json:"url"`
    Headers     http.Header `json:"headers"`
    QueryParams url.Values  `json:"qs_params"`
    BodySize    int64      `json:"req_body_len"`
}

type ResponseLog struct {
    Status      int    `json:"status"`
    StatusClass string `json:"status_class"`
    Size        int64  `json:"rsp_body_len"`
}

func logEntry(entry LogEntry) error {
    data, err := json.Marshal(entry)
    if err != nil {
        return err
    }

    accessLog.Printf("%s\n", string(data))
    return nil
}

// Helper functions for sanitizing sensitive data
func sanitizeHeaders(headers http.Header) http.Header {
    sanitized := make(http.Header)
    for key, values := range headers {
        // Skip sensitive headers
        if isSensitiveHeader(key) {
            sanitized[key] = []string{"[REDACTED]"}
            continue
        }
        sanitized[key] = values
    }
    return sanitized
}

func sanitizeQueryParams(params url.Values) url.Values {
    sanitized := make(url.Values)
    for key, values := range params {
        // Skip sensitive parameter names
        if isSensitiveParam(key) {
            sanitized[key] = []string{"[REDACTED]"}
            continue
        }
        sanitized[key] = values
    }
    return sanitized
}

// Helper function to identify sensitive headers
func isSensitiveHeader(header string) bool {
    sensitiveHeaders := map[string]bool{
        "Authorization":     true,
        "Cookie":           true,
        "X-API-Key":        true,
        "X-Access-Token":   true,
        "Session-Token":    true,
        "X-CSRF-Token":     true,
        "Set-Cookie":       true,
        "Proxy-Authorization": true,
    }
    
    return sensitiveHeaders[http.CanonicalHeaderKey(header)]
}

// Helper function to identify sensitive parameters
func isSensitiveParam(param string) bool {
    sensitiveParams := map[string]bool{
        "password":    true,
        "token":      true,
        "api_key":    true,
        "apikey":     true,
        "secret":     true,
        "credential": true,
    }
    
    paramLower := strings.ToLower(param)
    return sensitiveParams[paramLower]
}

// Middleware to close idle connections
func idleTimeoutMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        ctx := r.Context()
        
        // Create a done channel
        done := make(chan bool)
        
        go func() {
            next.ServeHTTP(w, r)
            done <- true
        }()
        
        select {
        case <-done:
            return
        case <-ctx.Done():
            w.WriteHeader(http.StatusGatewayTimeout)
            return
        }
    })
}

// Metrics tracking
type Metrics struct {
    totalRequests    uint64
    activeRequests   int64
    responseLatencies []time.Duration
    statusCodes      map[int]uint64
    mu              sync.RWMutex
}

var serverMetrics = &Metrics{
    statusCodes: make(map[int]uint64),
}

func (m *Metrics) incrementRequests() {
    atomic.AddUint64(&m.totalRequests, 1)
}

func (m *Metrics) incrementActiveRequests() {
    atomic.AddInt64(&m.activeRequests, 1)
}

func (m *Metrics) decrementActiveRequests() {
    atomic.AddInt64(&m.activeRequests, -1)
}

func (m *Metrics) addLatency(d time.Duration) {
    m.mu.Lock()
    defer m.mu.Unlock()
    m.responseLatencies = append(m.responseLatencies, d)
    // Keep only last 1000 latencies
    if len(m.responseLatencies) > 1000 {
        m.responseLatencies = m.responseLatencies[1:]
    }
}

func (m *Metrics) recordStatusCode(code int) {
    m.mu.Lock()
    defer m.mu.Unlock()
    m.statusCodes[code]++
}

// Metrics middleware
func metricsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        serverMetrics.incrementRequests()
        serverMetrics.incrementActiveRequests()
        defer serverMetrics.decrementActiveRequests()
        
        start := time.Now()
        
        // Create custom response writer to capture status code
        rw := &responseWriter{
            ResponseWriter: w,
            status:        http.StatusOK,
        }
        
        next.ServeHTTP(rw, r)
        
        duration := time.Since(start)
        serverMetrics.addLatency(duration)
        serverMetrics.recordStatusCode(rw.status)
    })
}

// Metrics endpoint handler
func metricsHandler(w http.ResponseWriter, r *http.Request) {
    serverMetrics.mu.RLock()
    defer serverMetrics.mu.RUnlock()
    
    var avgLatency time.Duration
    if len(serverMetrics.responseLatencies) > 0 {
        var sum time.Duration
        for _, lat := range serverMetrics.responseLatencies {
            sum += lat
        }
        avgLatency = sum / time.Duration(len(serverMetrics.responseLatencies))
    }
    
    metrics := struct {
        TotalRequests    uint64            `json:"total_requests"`
        ActiveRequests   int64             `json:"active_requests"`
        AverageLatency   string            `json:"average_latency"`
        StatusCodes      map[int]uint64    `json:"status_codes"`
    }{
        TotalRequests:   atomic.LoadUint64(&serverMetrics.totalRequests),
        ActiveRequests:  atomic.LoadInt64(&serverMetrics.activeRequests),
        AverageLatency:  avgLatency.String(),
        StatusCodes:     serverMetrics.statusCodes,
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(metrics)
}