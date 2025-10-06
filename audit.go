package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// AuditTools provides security auditing utilities
type AuditTools struct{}

// AuditLog represents an audit log entry
type AuditLog struct {
	Timestamp   string                 `json:"timestamp"`
	EventType   string                 `json:"eventType"`
	UserID      string                 `json:"userID,omitempty"`
	Action      string                 `json:"action"`
	Resource    string                 `json:"resource,omitempty"`
	Result      string                 `json:"result"`
	IPAddress   string                 `json:"ipAddress,omitempty"`
	UserAgent   string                 `json:"userAgent,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Severity    string                 `json:"severity"`
	SessionID   string                 `json:"sessionID,omitempty"`
}

// SecurityEvent represents a security event
type SecurityEvent struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
	Severity    string    `json:"severity"`
	Source      string    `json:"source"`
	Data        map[string]interface{} `json:"data"`
}

// CreateAuditLog creates a new audit log entry
func (a *AuditTools) CreateAuditLog(eventType, userID, action, resource, result string) *AuditLog {
	return &AuditLog{
		Timestamp: time.Now().Format(time.RFC3339),
		EventType: eventType,
		UserID:    userID,
		Action:    action,
		Resource:  resource,
		Result:    result,
		Severity:  a.determineSeverity(eventType, result),
	}
}

// determineSeverity determines log severity based on event type and result
func (a *AuditTools) determineSeverity(eventType, result string) string {
	if strings.Contains(result, "failed") || strings.Contains(result, "error") {
		return "ERROR"
	}
	
	switch eventType {
	case "authentication", "authorization":
		if result == "success" {
			return "INFO"
		}
		return "WARNING"
	case "data_access", "configuration_change":
		return "WARNING"
	case "security_violation":
		return "CRITICAL"
	default:
		return "INFO"
	}
}

// LogSecurityEvent logs a security event
func (a *AuditTools) LogSecurityEvent(eventType, description, severity string, data map[string]interface{}) *SecurityEvent {
	return &SecurityEvent{
		ID:          a.generateEventID(),
		Type:        eventType,
		Description: description,
		Timestamp:   time.Now(),
		Severity:    severity,
		Data:        data,
	}
}

// generateEventID generates a unique event ID
func (a *AuditTools) generateEventID() string {
	timestamp := time.Now().UnixNano()
	data := fmt.Sprintf("%d", timestamp)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8])
}

// WriteAuditLog writes audit log to file
func (a *AuditTools) WriteAuditLog(log *AuditLog, filename string) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	
	logJSON, err := json.Marshal(log)
	if err != nil {
		return err
	}
	
	_, err = file.WriteString(string(logJSON) + "\n")
	return err
}

// ReadAuditLogs reads audit logs from file
func (a *AuditTools) ReadAuditLogs(filename string) ([]*AuditLog, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	
	lines := strings.Split(string(data), "\n")
	var logs []*AuditLog
	
	for _, line := range lines {
		if line == "" {
			continue
		}
		
		var log AuditLog
		if err := json.Unmarshal([]byte(line), &log); err != nil {
			continue
		}
		
		logs = append(logs, &log)
	}
	
	return logs, nil
}

// FilterAuditLogs filters audit logs by criteria
func (a *AuditTools) FilterAuditLogs(logs []*AuditLog, criteria map[string]string) []*AuditLog {
	var filtered []*AuditLog
	
	for _, log := range logs {
		match := true
		
		if userID, ok := criteria["userID"]; ok && log.UserID != userID {
			match = false
		}
		
		if eventType, ok := criteria["eventType"]; ok && log.EventType != eventType {
			match = false
		}
		
		if severity, ok := criteria["severity"]; ok && log.Severity != severity {
			match = false
		}
		
		if action, ok := criteria["action"]; ok && !strings.Contains(log.Action, action) {
			match = false
		}
		
		if match {
			filtered = append(filtered, log)
		}
	}
	
	return filtered
}

// GenerateAuditReport generates an audit report
func (a *AuditTools) GenerateAuditReport(logs []*AuditLog) string {
	var report strings.Builder
	
	report.WriteString("=== Security Audit Report ===\n")
	report.WriteString(fmt.Sprintf("Generated: %s\n", time.Now().Format(time.RFC3339)))
	report.WriteString(fmt.Sprintf("Total Entries: %d\n\n", len(logs)))
	
	// Count by severity
	severityCounts := make(map[string]int)
	for _, log := range logs {
		severityCounts[log.Severity]++
	}
	
	report.WriteString("Entries by Severity:\n")
	for severity, count := range severityCounts {
		report.WriteString(fmt.Sprintf("  %s: %d\n", severity, count))
	}
	report.WriteString("\n")
	
	// Count by event type
	eventCounts := make(map[string]int)
	for _, log := range logs {
		eventCounts[log.EventType]++
	}
	
	report.WriteString("Entries by Event Type:\n")
	for eventType, count := range eventCounts {
		report.WriteString(fmt.Sprintf("  %s: %d\n", eventType, count))
	}
	report.WriteString("\n")
	
	// Recent critical events
	report.WriteString("Recent Critical Events:\n")
	criticalCount := 0
	for _, log := range logs {
		if log.Severity == "CRITICAL" && criticalCount < 10 {
			report.WriteString(fmt.Sprintf("  [%s] %s: %s\n", log.Timestamp, log.EventType, log.Action))
			criticalCount++
		}
	}
	
	if criticalCount == 0 {
		report.WriteString("  None\n")
	}
	
	report.WriteString("\n=== End of Report ===\n")
	
	return report.String()
}

// DetectAnomalies detects anomalies in audit logs
func (a *AuditTools) DetectAnomalies(logs []*AuditLog) []map[string]interface{} {
	var anomalies []map[string]interface{}
	
	// Track failed login attempts
	failedLogins := make(map[string]int)
	
	for _, log := range logs {
		if log.EventType == "authentication" && log.Result == "failed" {
			failedLogins[log.UserID]++
		}
	}
	
	// Detect multiple failed logins
	for userID, count := range failedLogins {
		if count >= 5 {
			anomalies = append(anomalies, map[string]interface{}{
				"type":        "multiple_failed_logins",
				"userID":      userID,
				"count":       count,
				"description": fmt.Sprintf("User %s had %d failed login attempts", userID, count),
			})
		}
	}
	
	// Detect unusual access patterns
	accessPatterns := make(map[string][]string)
	for _, log := range logs {
		if log.UserID != "" {
			accessPatterns[log.UserID] = append(accessPatterns[log.UserID], log.IPAddress)
		}
	}
	
	for userID, ips := range accessPatterns {
		uniqueIPs := make(map[string]bool)
		for _, ip := range ips {
			uniqueIPs[ip] = true
		}
		
		if len(uniqueIPs) > 5 {
			anomalies = append(anomalies, map[string]interface{}{
				"type":        "multiple_ip_addresses",
				"userID":      userID,
				"count":       len(uniqueIPs),
				"description": fmt.Sprintf("User %s accessed from %d different IP addresses", userID, len(uniqueIPs)),
			})
		}
	}
	
	return anomalies
}

// CalculateRiskScore calculates risk score for audit logs
func (a *AuditTools) CalculateRiskScore(logs []*AuditLog) float64 {
	if len(logs) == 0 {
		return 0.0
	}
	
	score := 0.0
	
	for _, log := range logs {
		switch log.Severity {
		case "CRITICAL":
			score += 10.0
		case "ERROR":
			score += 5.0
		case "WARNING":
			score += 2.0
		case "INFO":
			score += 0.1
		}
		
		if log.Result == "failed" {
			score += 1.0
		}
	}
	
	// Normalize by number of logs
	return score / float64(len(logs))
}

// ExportAuditLogsCSV exports audit logs to CSV format
func (a *AuditTools) ExportAuditLogsCSV(logs []*AuditLog) string {
	var csv strings.Builder
	
	// Header
	csv.WriteString("Timestamp,EventType,UserID,Action,Resource,Result,Severity,IPAddress\n")
	
	// Data
	for _, log := range logs {
		csv.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s\n",
			log.Timestamp,
			log.EventType,
			log.UserID,
			log.Action,
			log.Resource,
			log.Result,
			log.Severity,
			log.IPAddress,
		))
	}
	
	return csv.String()
}

// ValidateAuditLogIntegrity validates audit log integrity
func (a *AuditTools) ValidateAuditLogIntegrity(logs []*AuditLog) bool {
	if len(logs) == 0 {
		return true
	}
	
	// Check for proper timestamp ordering
	for i := 1; i < len(logs); i++ {
		t1, err1 := time.Parse(time.RFC3339, logs[i-1].Timestamp)
		t2, err2 := time.Parse(time.RFC3339, logs[i].Timestamp)
		
		if err1 != nil || err2 != nil {
			return false
		}
		
		if t2.Before(t1) {
			return false
		}
	}
	
	// Check for required fields
	for _, log := range logs {
		if log.Timestamp == "" || log.EventType == "" || log.Action == "" {
			return false
		}
	}
	
	return true
}

// ArchiveOldLogs archives logs older than specified days
func (a *AuditTools) ArchiveOldLogs(logs []*AuditLog, daysToKeep int) ([]*AuditLog, []*AuditLog) {
	cutoffTime := time.Now().AddDate(0, 0, -daysToKeep)
	
	var recent []*AuditLog
	var archived []*AuditLog
	
	for _, log := range logs {
		timestamp, err := time.Parse(time.RFC3339, log.Timestamp)
		if err != nil {
			continue
		}
		
		if timestamp.Before(cutoffTime) {
			archived = append(archived, log)
		} else {
			recent = append(recent, log)
		}
	}
	
	return recent, archived
}

// GenerateComplianceReport generates a compliance report
func (a *AuditTools) GenerateComplianceReport(logs []*AuditLog) string {
	var report strings.Builder
	
	report.WriteString("=== Compliance Report ===\n")
	report.WriteString(fmt.Sprintf("Report Date: %s\n\n", time.Now().Format("2006-01-02")))
	
	// Check authentication logs
	authCount := 0
	for _, log := range logs {
		if log.EventType == "authentication" {
			authCount++
		}
	}
	report.WriteString(fmt.Sprintf("Authentication Events: %d\n", authCount))
	
	// Check data access logs
	dataAccessCount := 0
	for _, log := range logs {
		if log.EventType == "data_access" {
			dataAccessCount++
		}
	}
	report.WriteString(fmt.Sprintf("Data Access Events: %d\n", dataAccessCount))
	
	// Check configuration changes
	configChangeCount := 0
	for _, log := range logs {
		if log.EventType == "configuration_change" {
			configChangeCount++
		}
	}
	report.WriteString(fmt.Sprintf("Configuration Changes: %d\n", configChangeCount))
	
	// Security violations
	violationCount := 0
	for _, log := range logs {
		if log.EventType == "security_violation" {
			violationCount++
		}
	}
	report.WriteString(fmt.Sprintf("Security Violations: %d\n", violationCount))
	
	report.WriteString("\n")
	
	// Compliance checks
	report.WriteString("Compliance Checks:\n")
	
	if authCount > 0 {
		report.WriteString("  ✓ Authentication logging enabled\n")
	} else {
		report.WriteString("  ✗ No authentication events logged\n")
	}
	
	if dataAccessCount > 0 {
		report.WriteString("  ✓ Data access logging enabled\n")
	} else {
		report.WriteString("  ✗ No data access events logged\n")
	}
	
	if violationCount == 0 {
		report.WriteString("  ✓ No security violations detected\n")
	} else {
		report.WriteString(fmt.Sprintf("  ⚠ %d security violations detected\n", violationCount))
	}
	
	report.WriteString("\n=== End of Compliance Report ===\n")
	
	return report.String()
}

// TrackUserActivity tracks user activity from logs
func (a *AuditTools) TrackUserActivity(logs []*AuditLog, userID string) map[string]interface{} {
	activity := make(map[string]interface{})
	
	var userLogs []*AuditLog
	for _, log := range logs {
		if log.UserID == userID {
			userLogs = append(userLogs, log)
		}
	}
	
	activity["totalEvents"] = len(userLogs)
	
	// Count by event type
	eventTypes := make(map[string]int)
	for _, log := range userLogs {
		eventTypes[log.EventType]++
	}
	activity["eventTypes"] = eventTypes
	
	// Recent activity
	recentCount := 0
	if len(userLogs) > 10 {
		recentCount = 10
	} else {
		recentCount = len(userLogs)
	}
	
	recent := userLogs[len(userLogs)-recentCount:]
	activity["recentActivity"] = recent
	
	// First and last seen
	if len(userLogs) > 0 {
		activity["firstSeen"] = userLogs[0].Timestamp
		activity["lastSeen"] = userLogs[len(userLogs)-1].Timestamp
	}
	
	return activity
}

// DisplayAuditTools shows available audit tools
func DisplayAuditTools() {
	fmt.Println("\n=== Security Audit Tools ===")
	fmt.Println("1. Create Audit Log Entry")
	fmt.Println("2. Generate Audit Report")
	fmt.Println("3. Detect Anomalies")
	fmt.Println("4. Calculate Risk Score")
	fmt.Println("5. Generate Compliance Report")
}
