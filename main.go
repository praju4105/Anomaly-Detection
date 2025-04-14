package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// --- Configuration --- //
const (
	LOCAL_MALICIOUS_UA_FILE = "malicious_user_agents.txt" // Ensure this file exists

	// Behavioral Blocking Config
	MAX_REQUESTS_PER_MINUTE       = 100             // Requests per minute allowed
	BEHAVIORAL_ANALYSIS_WINDOW    = 1 * time.Minute // Use time.Duration for clarity (Python had 3600s=1hr) - ADJUST AS NEEDED
	USER_AGENT_ROTATION_THRESHOLD = 5               // Block IP if more than this many unique UAs seen in window
	IP_BLOCK_DURATION             = 1 * time.Hour   // How long to block an IP based on behavior

	// Request Risk Scoring Config
	REQUEST_RISK_THRESHOLD   = 10 // Block individual request if total risk score >= this value
	ENABLE_BEHAVIORAL_CHECKS = false

	// Points (simplified from Python, adjust as needed)
	SCORE_EMPTY_UA                = 5
	SCORE_MALICIOUS_UA_LIST_MATCH = 10 // Higher score for direct match
	SCORE_SUSPICIOUS_UA_KEYWORD   = 3
	SCORE_UA_STRUCTURE_ISSUE      = 2
	SCORE_UA_LENGTH_ISSUE         = 2
	SCORE_UA_SUSPICIOUS_CHARS     = 3
	SCORE_LEGIT_UA_PATTERN        = -5 // Negative score (boost)

	SCORE_PATH_TRAVERSAL        = 5
	SCORE_PATH_SENSITIVE_ACCESS = 5
	SCORE_PATH_ADMIN_ACCESS     = 4
	SCORE_PATH_SENSITIVE_EXT    = 4
	SCORE_PATH_NULL_BYTE        = 5
	SCORE_PATH_ENCODING_ISSUE   = 3
	SCORE_PATH_SQLI_XSS         = 4
	SCORE_PATH_SUSPICIOUS_CHARS = 2
	SCORE_PATH_DEPTH_LENGTH     = 2

	// Behavioral Check Cleanup Interval
	CLEANUP_INTERVAL = 10 * time.Minute
)

// --- Dynamic Data Stores --- //
var (
	maliciousUserAgents map[string]struct{} // Use a map for efficient lookups
	ipBehaviorDB        map[string]*IPBehavior
	ipBehaviorMutex     sync.Mutex // Mutex to protect concurrent access to ipBehaviorDB
)

// IPBehavior stores tracking data for an IP address
type IPBehavior struct {
	Requests     []time.Time         // Timestamps of requests within the window
	UserAgents   map[string]struct{} // Set of unique user agents seen in the window
	BlockedUntil time.Time           // Timestamp when IP block expires
}

// --- Initialization --- //
func init() {
	log.Println("--- Initializing Security Service ---")
	loadMaliciousUserAgents()
	initializeBehavioralDB()
	go startCleanupRoutine()
	legitPatterns := []string{
		`^Mozilla/5\.0 \(Windows NT [\d\.]+; (Win64; x64|WOW64|x64)\) AppleWebKit/[\d\.]+ \(KHTML, like Gecko\) Chrome/[\d\.]+ Safari/[\d\.]+( Edg/[\d\.]+)?$`, // Chrome/Edge Win
		`^Mozilla/5\.0 \(Macintosh; Intel Mac OS X [\d_\.]+\) AppleWebKit/[\d\.]+ \(KHTML, like Gecko\) Version/[\d\.]+ Safari/[\d\.]+$`,                       // Safari Mac
		`^Mozilla/5\.0 \(Windows NT [\d\.]+; (Win64; x64|WOW64); rv:[\d\.]+\) Gecko/[\d]+ Firefox/[\d\.]+$`,                                                    // Firefox Win
		`^Mozilla/5\.0 \(Linux; Android [\d\.\w\s\-;()]+?\) AppleWebKit/[\d\.]+ \(KHTML, like Gecko\) Chrome/[\d\.]+ (Mobile )?Safari/[\d\.]+$`,                // Android Chrome (flexible)
		`^Mozilla/5\.0 \(iPhone; CPU iPhone OS [\d_]+ like Mac OS X\) AppleWebKit/[\d\.]+ \(KHTML, like Gecko\) Version/[\d\.]+ Mobile/[\w]+ Safari/[\d\.]+$`,  // iPhone Safari
		`^Mozilla/5\.0 \(compatible; Googlebot/2\.1; \+http://www.google.com/bot\.html\)$`,                                                                     // Googlebot
		`^Mozilla/5\.0 \(compatible; Bingbot/2\.0; \+http://www.bing.com/bingbot\.htm\)$`,                                                                      // Bingbot
		`^python-requests/.*`,
		`^curl/.*`,
		`^Wget/.*`,
		// Add more known good patterns here
	}
	uaLegitPatternsRegex = make([]*regexp.Regexp, 0, len(legitPatterns))
	for _, pattern := range legitPatterns {
		// Use MustCompile - panics on error, which is fine during init
		uaLegitPatternsRegex = append(uaLegitPatternsRegex, regexp.MustCompile(pattern))
	}
	// Start background cleanup for IP behavior DB
}

// --- Threat Intelligence Loading --- //
func loadMaliciousUserAgents() {
	maliciousUserAgents = make(map[string]struct{}) // Initialize the map
	log.Printf("Attempting to load malicious user agents from: %s\n", LOCAL_MALICIOUS_UA_FILE)

	file, err := os.Open(LOCAL_MALICIOUS_UA_FILE)
	if err != nil {
		log.Printf("  WARNING: Could not open local user agent file '%s': %v. No local UAs loaded.", LOCAL_MALICIOUS_UA_FILE, err)
		return // Continue without local UAs if file is missing
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Ignore empty lines and comments
		if line != "" && !strings.HasPrefix(line, "#") {
			maliciousUserAgents[line] = struct{}{} // Add UA to the map (value doesn't matter)
			count++
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("  ERROR: Reading local user agent file '%s': %v", LOCAL_MALICIOUS_UA_FILE, err)
	} else {
		log.Printf("  Successfully loaded %d user agents from %s\n", count, LOCAL_MALICIOUS_UA_FILE)
	}
	log.Println("------------------------------------------")
}

// --- Behavioral DB Initialization and Cleanup --- //
func initializeBehavioralDB() {
	ipBehaviorDB = make(map[string]*IPBehavior)
	log.Println("Initialized IP Behavior Database.")
}

// startCleanupRoutine runs periodically to remove old entries from ipBehaviorDB
func startCleanupRoutine() {
	ticker := time.NewTicker(CLEANUP_INTERVAL)
	defer ticker.Stop()

	log.Printf("Starting IP Behavior DB cleanup routine (runs every %v)", CLEANUP_INTERVAL)

	for range ticker.C {
		cleanupOldIPEntries()
	}
}

// cleanupOldIPEntries removes expired blocks and IPs with no recent activity.
func cleanupOldIPEntries() {
	ipBehaviorMutex.Lock()
	defer ipBehaviorMutex.Unlock()

	now := time.Now()
	cleanedCount := 0
	activeCount := 0 // Count entries remaining after cleanup

	for ip, behavior := range ipBehaviorDB {
		// Remove expired block status
		if !behavior.BlockedUntil.IsZero() && now.After(behavior.BlockedUntil) {
			log.Printf("  DEBUG Behavior Cleanup: Unblocking IP %s (block expired)", ip)
			behavior.BlockedUntil = time.Time{} // Reset block time
			// Keep the entry for now, but clear its requests/UAs if old
		}

		// Prune old requests from the slice (efficiently without creating new slices often)
		n := 0
		windowStartTime := now.Add(-BEHAVIORAL_ANALYSIS_WINDOW)
		for _, ts := range behavior.Requests {
			if ts.After(windowStartTime) || ts.Equal(windowStartTime) {
				behavior.Requests[n] = ts
				n++
			}
		}
		behavior.Requests = behavior.Requests[:n]

		// If the entry is not blocked and has no recent requests, remove it
		if behavior.BlockedUntil.IsZero() && len(behavior.Requests) == 0 {
			log.Printf("  DEBUG Behavior Cleanup: Removing inactive IP %s from DB", ip)
			delete(ipBehaviorDB, ip)
			cleanedCount++
		} else {
			activeCount++ // Count entries that remain
		}
	}
	if cleanedCount > 0 {
		log.Printf("IP Behavior DB Cleanup: Removed %d inactive entries. %d entries remain.", cleanedCount, activeCount)
	}
}

// --- Placeholders for Detection Functions (We will fill these next) --- //

var (
	uaSuspiciousCharsRegex = regexp.MustCompile(`[^a-zA-Z0-9\s\(\)\[\]\./;:,+\-_@]`)
	uaLegitPatternsRegex   []*regexp.Regexp
)

func getUserAgentSuspicionScore(userAgent string) int {

	if userAgent == "" {
		log.Println("  DEBUG UA Check: Empty User-Agent (+", SCORE_EMPTY_UA, ")")
		return SCORE_EMPTY_UA
	}

	score := 0
	uaLower := strings.ToLower(userAgent)
	log.Printf("  DEBUG UA Check: Analyzing '%s'", userAgent)

	// --- Check against known malicious UA list (Exact Match) ---
	if _, found := maliciousUserAgents[userAgent]; found { // Check original case first if list is precise
		log.Println("  DEBUG UA Match (Malicious List - Exact): Found match (+", SCORE_MALICIOUS_UA_LIST_MATCH, ")")
		score += SCORE_MALICIOUS_UA_LIST_MATCH
		// Can potentially return early if list match is critical
		// return score
	} else {
		// Fallback: Check case-insensitively IF exact match failed
		// This requires the list keys to also be potentially lowercase,
		// or iterate and compare lowercase (less efficient).
		// For simplicity with the map lookup, we prioritize exact match.
		// If case-insensitive list check is needed, load list keys in lower too.
	}

	// --- Keyword-based checks ---
	suspiciousKeywords := map[string]int{
		"sqlmap": SCORE_SUSPICIOUS_UA_KEYWORD + 2, "nmap": SCORE_SUSPICIOUS_UA_KEYWORD + 2, // Higher score
		"scan": SCORE_SUSPICIOUS_UA_KEYWORD, "bot": SCORE_SUSPICIOUS_UA_KEYWORD - 1, // Lower score for generic bot
		"spider": SCORE_SUSPICIOUS_UA_KEYWORD - 1, "crawl": SCORE_SUSPICIOUS_UA_KEYWORD - 1,
		"nikto": SCORE_SUSPICIOUS_UA_KEYWORD + 1, "acunetix": SCORE_SUSPICIOUS_UA_KEYWORD + 2,
		"netsparker": SCORE_SUSPICIOUS_UA_KEYWORD + 2, "masscan": SCORE_SUSPICIOUS_UA_KEYWORD + 1,
		"dirbuster": SCORE_SUSPICIOUS_UA_KEYWORD + 1, "gobuster": SCORE_SUSPICIOUS_UA_KEYWORD + 1,
		"exploit": SCORE_SUSPICIOUS_UA_KEYWORD + 2, "shell": SCORE_SUSPICIOUS_UA_KEYWORD + 1,
		// Add more keywords as needed
	}
	for kw, kwScore := range suspiciousKeywords {
		if strings.Contains(uaLower, kw) {
			log.Println("  DEBUG UA Match (Keyword): Found keyword '", kw, "' (+", kwScore, ")")
			score += kwScore
		}
	}

	// --- Structural and Format Checks ---
	uaLen := len(userAgent)
	if uaLen < 10 && !strings.Contains(uaLower, "curl") && !strings.Contains(uaLower, "wget") {
		log.Println("  DEBUG UA Match (Length): Very short UA (+", SCORE_UA_LENGTH_ISSUE, ")")
		score += SCORE_UA_LENGTH_ISSUE
	} else if uaLen > 250 { // Adjusted length limit
		log.Println("  DEBUG UA Match (Length): Excessive length UA (+", SCORE_UA_LENGTH_ISSUE, ")")
		score += SCORE_UA_LENGTH_ISSUE
	}

	// Very generic UA check
	genericUAs := map[string]struct{}{"mozilla": {}, "chrome": {}, "safari": {}, "firefox": {}, "opera": {}, "webkit": {}}
	if _, isGeneric := genericUAs[uaLower]; isGeneric {
		log.Println("  DEBUG UA Match (Structure): Overly generic UA (+", SCORE_UA_STRUCTURE_ISSUE+1, ")")
		score += SCORE_UA_STRUCTURE_ISSUE + 1
	}

	// Check for suspicious characters
	if uaSuspiciousCharsRegex.MatchString(userAgent) {
		log.Println("  DEBUG UA Match (Characters): Suspicious characters found (+", SCORE_UA_SUSPICIOUS_CHARS, ")")
		score += SCORE_UA_SUSPICIOUS_CHARS
	}
	// Check for unbalanced parentheses
	if strings.Count(userAgent, "(") != strings.Count(userAgent, ")") {
		log.Println("  DEBUG UA Match (Structure): Unbalanced parentheses (+", SCORE_UA_STRUCTURE_ISSUE, ")")
		score += SCORE_UA_STRUCTURE_ISSUE
	}

	// --- Legitimacy Boost ---
	// Check against known good patterns (full match)
	for _, pattern := range uaLegitPatternsRegex {
		if pattern.MatchString(userAgent) {
			log.Println("  DEBUG UA Match (Legitimate Pattern): Matched known good pattern (+", SCORE_LEGIT_UA_PATTERN, ")")
			score += SCORE_LEGIT_UA_PATTERN
			break // Stop checking once a legit pattern matches
		}
	}

	// Ensure score doesn't go below zero
	if score < 0 {
		score = 0
	}

	log.Printf("  DEBUG UA Final Score: %d for '%s'", score, userAgent)
	return score
}

var (
	// Path Traversal & Encoding
	pathTraversalRegex = regexp.MustCompile(`\.\.[/\\]|%2e%2e|%252e%252e`) // Basic, encoded, double encoded
	// Sensitive Files/Dirs
	pathSensitiveFileRegex = regexp.MustCompile(`(?i)/etc/(passwd|shadow|group)|\\windows\\(system32|syswow64)|/\.(git|svn|hg|env|dockerenv)|wp-config\.php|id_rsa|id_dsa`)
	// Admin Interfaces
	pathAdminRegex = regexp.MustCompile(`(?i)wp-admin|wp-login|administrator|phpmyadmin|server-status|jmx-console|web-console`)
	// Sensitive Extensions
	pathSensitiveExtRegex = regexp.MustCompile(`(?i)\.(bak|config|sql|conf|ini|log|env|pem|key|yml|yaml|toml|htpasswd|sh|bash|exe|dll|zip|gz|tar|jar)$`)
	// Injection/Misc
	pathNullByteRegex        = regexp.MustCompile(`%00|\x00`)
	pathBasicSQLiRegex       = regexp.MustCompile(`(?i)('|\%27).*(or|union|select|insert|update|delete)|(;|--|\%20)`) // Simplified
	pathBasicXSSRegex        = regexp.MustCompile(`(?i)<script|%3Cscript|onerror=|onload=|javascript:`)               // Simplified
	pathSuspiciousCharsRegex = regexp.MustCompile(`[^\w/\.\-~:@!$&'()*+,;=%?#\[\]]`)                                  // Allowed chars in path/query
)

// REPLACE your function with this one:
func getPathSuspicionScore(path string) int { // 'path' here is the original RequestURI
	if path == "" || path == "/" {
		return 0 // No score for empty or root path
	}

	originalPathForLogging := path // Keep a copy of the original input for the final log
	score := 0
	log.Printf("  DEBUG Path Check: Analyzing original path: '%s'", originalPathForLogging)

	// --- Decoding ---
	// Use the improved decoding logic:
	decodedPath := path               // Start with the original path
	decodingOccurred := false         // Flag to see if decoding actually changed anything
	lastDecodedPathBeforeLoop := path // Track previous state for comparison
	for i := 0; i < 3; i++ {          // Limit decoding attempts
		tempDecodedPath, err := url.PathUnescape(lastDecodedPathBeforeLoop) // Decode the *previous* state
		if err != nil {
			log.Printf("  DEBUG Path Check: Decoding error on attempt %d: %v (+%d)", i+1, err, SCORE_PATH_ENCODING_ISSUE)
			score += SCORE_PATH_ENCODING_ISSUE
			// Keep the last successfully decoded path instead of reverting fully
			decodedPath = lastDecodedPathBeforeLoop
			break // Stop decoding on error
		}

		if tempDecodedPath == lastDecodedPathBeforeLoop { // Check if decoding stabilized
			// No change from previous state, stop.
			break
		}

		// If we got here, decoding changed the string
		decodingOccurred = true
		decodedPath = tempDecodedPath           // Store the new decoded value
		lastDecodedPathBeforeLoop = decodedPath // Update the state for the next loop comparison
	}

	if decodingOccurred {
		log.Printf("  DEBUG Path Check: Final decoded path after loop: '%s'", decodedPath)
	} else {
		log.Printf("  DEBUG Path Check: Path was not URL encoded or decoding loop finished: '%s'", decodedPath)
	}

	// --->>> DETAILED LOGGING FOR EACH REGEX <<<---
	log.Printf("  DEBUG Path Check: === Applying Regex Checks on Decoded Path: '%s' ===", decodedPath)

	// --- Apply Regex Checks (on decoded path) ---
	matchTraversal := pathTraversalRegex.MatchString(decodedPath)
	log.Printf("  DEBUG Path Regex Check: pathTraversalRegex -> %t", matchTraversal)
	if matchTraversal {
		log.Println("    MATCH: Traversal pattern found (+", SCORE_PATH_TRAVERSAL, ")")
		score += SCORE_PATH_TRAVERSAL
	}

	matchSensitiveFile := pathSensitiveFileRegex.MatchString(decodedPath)
	log.Printf("  DEBUG Path Regex Check: pathSensitiveFileRegex -> %t", matchSensitiveFile)
	if matchSensitiveFile {
		log.Println("    MATCH: Sensitive file/dir access attempt (+", SCORE_PATH_SENSITIVE_ACCESS, ")")
		score += SCORE_PATH_SENSITIVE_ACCESS
	}

	matchAdmin := pathAdminRegex.MatchString(decodedPath)
	log.Printf("  DEBUG Path Regex Check: pathAdminRegex -> %t", matchAdmin)
	if matchAdmin {
		log.Println("    MATCH: Admin interface access attempt (+", SCORE_PATH_ADMIN_ACCESS, ")")
		score += SCORE_PATH_ADMIN_ACCESS
	}

	matchSensitiveExt := pathSensitiveExtRegex.MatchString(decodedPath)
	log.Printf("  DEBUG Path Regex Check: pathSensitiveExtRegex -> %t", matchSensitiveExt)
	if matchSensitiveExt {
		log.Println("    MATCH: Sensitive file extension found (+", SCORE_PATH_SENSITIVE_EXT, ")")
		score += SCORE_PATH_SENSITIVE_EXT
	}

	matchNullByte := pathNullByteRegex.MatchString(decodedPath)
	log.Printf("  DEBUG Path Regex Check: pathNullByteRegex -> %t", matchNullByte)
	if matchNullByte {
		log.Println("    MATCH: Null byte detected (+", SCORE_PATH_NULL_BYTE, ")")
		score += SCORE_PATH_NULL_BYTE
	}

	matchSQLi := pathBasicSQLiRegex.MatchString(decodedPath)
	log.Printf("  DEBUG Path Regex Check: pathBasicSQLiRegex -> %t", matchSQLi)
	if matchSQLi {
		log.Println("    MATCH: Basic SQLi pattern found (+", SCORE_PATH_SQLI_XSS, ")")
		score += SCORE_PATH_SQLI_XSS
	}

	matchXSS := pathBasicXSSRegex.MatchString(decodedPath)
	log.Printf("  DEBUG Path Regex Check: pathBasicXSSRegex -> %t", matchXSS)
	if matchXSS {
		log.Println("    MATCH: Basic XSS pattern found (+", SCORE_PATH_SQLI_XSS, ")")
		score += SCORE_PATH_SQLI_XSS
	}

	// --- Structural Checks (Applied to decodedPath) ---
	log.Printf("  DEBUG Path Check: === Applying Structural Checks on Decoded Path: '%s' ===", decodedPath)
	// Check path depth (count slashes)
	depth := strings.Count(decodedPath, "/")
	if depth > 15 {
		log.Println("  DEBUG Path Structural Check: Excessive depth (", depth, " slashes) (+", SCORE_PATH_DEPTH_LENGTH, ")")
		score += SCORE_PATH_DEPTH_LENGTH
	} else {
		log.Printf("  DEBUG Path Structural Check: Depth (%d) is OK.", depth)
	}

	// Check length
	pathLen := len(decodedPath)
	if pathLen > 500 { // Check total length of path + query
		log.Println("  DEBUG Path Structural Check: Excessive length (", pathLen, " chars) (+", SCORE_PATH_DEPTH_LENGTH, ")")
		score += SCORE_PATH_DEPTH_LENGTH
	} else {
		log.Printf("  DEBUG Path Structural Check: Length (%d) is OK.", pathLen)
	}

	// Check for suspicious chars not typically found in URLs (after decoding)
	matchSuspiciousChars := pathSuspiciousCharsRegex.MatchString(decodedPath)
	log.Printf("  DEBUG Path Structural Check: pathSuspiciousCharsRegex -> %t", matchSuspiciousChars)
	if matchSuspiciousChars {
		log.Println("    MATCH: Suspicious characters found (+", SCORE_PATH_SUSPICIOUS_CHARS, ")")
		score += SCORE_PATH_SUSPICIOUS_CHARS
	}

	// Ensure score doesn't go below zero
	if score < 0 {
		score = 0
	}

	// Log final score with the original path for context
	log.Printf("  DEBUG Path Final Score: %d for original path '%s'", score, originalPathForLogging)
	return score
}

func checkIPBehavior(ip string, userAgent string) (bool, string) {

	ipBehaviorMutex.Lock()         // Lock before accessing shared map
	defer ipBehaviorMutex.Unlock() // Ensure unlock happens even on panic

	now := time.Now()
	behavior, exists := ipBehaviorDB[ip]

	// If IP not seen before, create a new entry
	if !exists {
		behavior = &IPBehavior{
			Requests:   make([]time.Time, 0, MAX_REQUESTS_PER_MINUTE*2), // Pre-allocate some capacity
			UserAgents: make(map[string]struct{}),
		}
		ipBehaviorDB[ip] = behavior
		log.Printf("  DEBUG Behavior: New IP %s seen. Tracking.", ip)
	}

	// --- Check if already blocked ---
	if !behavior.BlockedUntil.IsZero() && now.Before(behavior.BlockedUntil) {
		log.Printf("  DEBUG Behavior: IP %s currently BLOCKED BY BEHAVIOR until %s", ip, behavior.BlockedUntil.Format(time.RFC3339))
		return false, "IP currently blocked due to previous behavior"
	}
	// Reset block if it has expired
	if !behavior.BlockedUntil.IsZero() && now.After(behavior.BlockedUntil) {
		log.Printf("  DEBUG Behavior: IP %s behavior block expired. Resetting state.", ip)
		behavior.BlockedUntil = time.Time{}
		behavior.UserAgents = make(map[string]struct{})                     // Reset UAs on block expiry
		behavior.Requests = make([]time.Time, 0, MAX_REQUESTS_PER_MINUTE*2) // Reset requests
	}

	// --- Record current request ---
	behavior.Requests = append(behavior.Requests, now)
	// Normalize empty UA for tracking
	uaKey := userAgent
	if uaKey == "" {
		uaKey = "EMPTY_UA"
	}
	behavior.UserAgents[uaKey] = struct{}{} // Add/update UA in the set

	// --- Prune old requests (outside the analysis window) ---
	// This is also done by the cleanup routine, but doing it here ensures
	// the current check uses the most accurate window count.
	n := 0
	windowStartTime := now.Add(-BEHAVIORAL_ANALYSIS_WINDOW)
	for _, ts := range behavior.Requests {
		if ts.After(windowStartTime) || ts.Equal(windowStartTime) {
			behavior.Requests[n] = ts
			n++
		}
	}
	behavior.Requests = behavior.Requests[:n]

	// --- Check thresholds ---
	requestCountInWindow := len(behavior.Requests)
	uaRotationCount := len(behavior.UserAgents)

	// Calculate requests per minute equivalent for the window
	// Avoid division by zero if window is very small
	windowMinutes := BEHAVIORAL_ANALYSIS_WINDOW.Minutes()
	if windowMinutes < (1.0 / 60.0) { // Less than a second
		windowMinutes = 1.0 / 60.0
	}
	requestsPerMinuteEquivalent := float64(requestCountInWindow) / windowMinutes

	log.Printf("  DEBUG Behavior: IP %s Stats - Rate=%.2f req/min (Window: %d reqs), Unique UAs=%d",
		ip, requestsPerMinuteEquivalent, requestCountInWindow, uaRotationCount)

	blockReason := ""
	if requestsPerMinuteEquivalent > float64(MAX_REQUESTS_PER_MINUTE) {
		blockReason = fmt.Sprintf("Rate limit exceeded (%.2f req/min > %d)", requestsPerMinuteEquivalent, MAX_REQUESTS_PER_MINUTE)
	} else if uaRotationCount > USER_AGENT_ROTATION_THRESHOLD {
		blockReason = fmt.Sprintf("UA rotation threshold exceeded (%d unique UAs > %d)", uaRotationCount, USER_AGENT_ROTATION_THRESHOLD)
	}

	if blockReason != "" {
		behavior.BlockedUntil = now.Add(IP_BLOCK_DURATION)
		log.Printf("  BEHAVIORAL BLOCK: Blocking IP %s until %s. Reason: %s.", ip, behavior.BlockedUntil.Format(time.RFC3339), blockReason)
		return false, blockReason
	}

	// If no thresholds exceeded, the IP is allowed by behavior checks
	return true, ""

}

// --- Main Web Service Logic --- //

func main() {
	// Set Gin to release mode (optional, less verbose logs)
	// gin.SetMode(gin.ReleaseMode)

	router := gin.Default()

	// Define the /badinputs endpoint
	router.POST("/badinputs/*subpath", handleBadInputs)

	// Start the server
	port := "8080" // You can make this configurable
	log.Printf("Starting server on port %s\n", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// handleBadInputs is the handler for the /badinputs endpoint
func handleBadInputs(c *gin.Context) {
	startTime := time.Now()

	// --- Get Request Data ---
	ip := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")
	// Use RequestURI to get path + query string, similar to how security tools analyze
	//path := c.Request.URL.RequestURI()
	// If RequestURI is empty (e.g., HTTP/1.0), fall back to Path
	//if path == "" {
	//path = c.Request.URL.Path
	subpath := c.Param("subpath")
	path := "/" + subpath
	if c.Request.URL.RawQuery != "" {
		path += "?" + c.Request.URL.RawQuery
	}
	// Handle case where subpath is empty (request was exactly /badinputs/)
	if subpath == "" || subpath == "/" {
		path = "/" // Or decide how to handle the root case if needed
	}

	log.Printf("--- Received Request --- IP: %s, UA: '%s', Path: '%s'", ip, userAgent, path)

	// === STEP 1: Check IP Behavior (Rate Limiting / UA Rotation) ===
	if ENABLE_BEHAVIORAL_CHECKS {
		isAllowedByBehavior, blockReason := checkIPBehavior(ip, userAgent)
		if !isAllowedByBehavior {
			log.Printf("  >> RESULT: IP %s BLOCKED BY BEHAVIOR. Reason: %s. Request Denied.", ip, blockReason)
			c.JSON(http.StatusForbidden, gin.H{"status": "Request Not Accepted", "reason": "Behavioral Block"})
			log.Printf("--- Request Handled (Blocked by Behavior) in %v ---", time.Since(startTime))
			return // Stop processing
		}
		log.Println("  DEBUG Orchestration: IP allowed by behavior.")
	}

	// === STEP 2: Calculate Request-Specific Risk Score ===
	// Note: Skipping OpenAI call for now
	uaScore := getUserAgentSuspicionScore(userAgent)
	pathScore := getPathSuspicionScore(path)
	totalRiskScore := uaScore + pathScore

	log.Printf("  Risk Score Details: UA=%d, Path=%d -> TOTAL = %d", uaScore, pathScore, totalRiskScore)

	// === STEP 3: Decide based on Request Risk Threshold ===
	if totalRiskScore >= REQUEST_RISK_THRESHOLD {
		log.Printf("  >> RESULT: Request BLOCKED BY RISK (Score: %d >= Threshold: %d).", totalRiskScore, REQUEST_RISK_THRESHOLD)
		c.JSON(http.StatusForbidden, gin.H{"status": "Request Not Accepted", "reason": "High Risk Score"})
	} else {
		log.Printf("  >> RESULT: Request ALLOWED (Score: %d < Threshold: %d).", totalRiskScore, REQUEST_RISK_THRESHOLD)
		c.JSON(http.StatusOK, gin.H{"status": "Request Accepted"})
	}
	log.Printf("--- Request Handled in %v ---", time.Since(startTime))

}
