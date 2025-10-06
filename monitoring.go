package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// MonitoringTools provides system monitoring and logging utilities
type MonitoringTools struct {
	mu sync.Mutex
}

// SystemMetrics represents system metrics
type SystemMetrics struct {
	Timestamp      time.Time              `json:"timestamp"`
	CPUUsage       float64                `json:"cpuUsage"`
	MemoryUsage    float64                `json:"memoryUsage"`
	DiskUsage      float64                `json:"diskUsage"`
	NetworkTraffic map[string]interface{} `json:"networkTraffic"`
	ActiveSessions int                    `json:"activeSessions"`
	Uptime         int64                  `json:"uptime"`
}

// LogEntry represents a log entry
type LogEntry struct {
	Timestamp string                 `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Source    string                 `json:"source"`
	Data      map[string]interface{} `json:"data,omitempty"`
	TraceID   string                 `json:"traceID,omitempty"`
}

// Alert represents a security alert
type Alert struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Source      string    `json:"source"`
	Status      string    `json:"status"`
	Data        map[string]interface{} `json:"data"`
}

// CreateLogEntry creates a new log entry
func (m *MonitoringTools) CreateLogEntry(level, message, source string, data map[string]interface{}) *LogEntry {
	return &LogEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		Level:     level,
		Message:   message,
		Source:    source,
		Data:      data,
		TraceID:   m.generateTraceID(),
	}
}

// generateTraceID generates a unique trace ID
func (m *MonitoringTools) generateTraceID() string {
	data := fmt.Sprintf("%d", time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8])
}

// WriteLog writes a log entry to file
func (m *MonitoringTools) WriteLog(entry *LogEntry, filename string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	
	logJSON, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	
	_, err = file.WriteString(string(logJSON) + "\n")
	return err
}

// ReadLogs reads log entries from file
func (m *MonitoringTools) ReadLogs(filename string, limit int) ([]*LogEntry, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	
	lines := strings.Split(string(data), "\n")
	var logs []*LogEntry
	
	start := 0
	if limit > 0 && len(lines) > limit {
		start = len(lines) - limit
	}
	
	for i := start; i < len(lines); i++ {
		if lines[i] == "" {
			continue
		}
		
		var log LogEntry
		if err := json.Unmarshal([]byte(lines[i]), &log); err != nil {
			continue
		}
		
		logs = append(logs, &log)
	}
	
	return logs, nil
}

// FilterLogs filters logs by criteria
func (m *MonitoringTools) FilterLogs(logs []*LogEntry, level, source string, startTime, endTime time.Time) []*LogEntry {
	var filtered []*LogEntry
	
	for _, log := range logs {
		// Filter by level
		if level != "" && log.Level != level {
			continue
		}
		
		// Filter by source
		if source != "" && log.Source != source {
			continue
		}
		
		// Filter by time range
		timestamp, err := time.Parse(time.RFC3339, log.Timestamp)
		if err != nil {
			continue
		}
		
		if !startTime.IsZero() && timestamp.Before(startTime) {
			continue
		}
		
		if !endTime.IsZero() && timestamp.After(endTime) {
			continue
		}
		
		filtered = append(filtered, log)
	}
	
	return filtered
}

// AnalyzeLogs analyzes log entries for patterns
func (m *MonitoringTools) AnalyzeLogs(logs []*LogEntry) map[string]interface{} {
	analysis := make(map[string]interface{})
	
	// Count by level
	levelCounts := make(map[string]int)
	for _, log := range logs {
		levelCounts[log.Level]++
	}
	analysis["levelCounts"] = levelCounts
	
	// Count by source
	sourceCounts := make(map[string]int)
	for _, log := range logs {
		sourceCounts[log.Source]++
	}
	analysis["sourceCounts"] = sourceCounts
	
	// Error rate
	errorCount := levelCounts["ERROR"] + levelCounts["CRITICAL"]
	totalCount := len(logs)
	if totalCount > 0 {
		analysis["errorRate"] = float64(errorCount) / float64(totalCount) * 100
	}
	
	// Most active sources
	var topSources []string
	for source := range sourceCounts {
		topSources = append(topSources, source)
	}
	analysis["topSources"] = topSources
	
	return analysis
}

// CreateAlert creates a new alert
func (m *MonitoringTools) CreateAlert(alertType, severity, title, description, source string, data map[string]interface{}) *Alert {
	return &Alert{
		ID:          m.generateAlertID(),
		Timestamp:   time.Now(),
		Type:        alertType,
		Severity:    severity,
		Title:       title,
		Description: description,
		Source:      source,
		Status:      "open",
		Data:        data,
	}
}

// generateAlertID generates a unique alert ID
func (m *MonitoringTools) generateAlertID() string {
	data := fmt.Sprintf("alert-%d", time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8])
}

// SaveAlert saves an alert to file
func (m *MonitoringTools) SaveAlert(alert *Alert, filename string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	
	alertJSON, err := json.Marshal(alert)
	if err != nil {
		return err
	}
	
	_, err = file.WriteString(string(alertJSON) + "\n")
	return err
}

// GetAlerts retrieves alerts from file
func (m *MonitoringTools) GetAlerts(filename string, status string) ([]*Alert, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	
	lines := strings.Split(string(data), "\n")
	var alerts []*Alert
	
	for _, line := range lines {
		if line == "" {
			continue
		}
		
		var alert Alert
		if err := json.Unmarshal([]byte(line), &alert); err != nil {
			continue
		}
		
		if status == "" || alert.Status == status {
			alerts = append(alerts, &alert)
		}
	}
	
	return alerts, nil
}

// AcknowledgeAlert marks an alert as acknowledged
func (m *MonitoringTools) AcknowledgeAlert(alertID string, alerts []*Alert) bool {
	for _, alert := range alerts {
		if alert.ID == alertID {
			alert.Status = "acknowledged"
			return true
		}
	}
	return false
}

// CloseAlert marks an alert as closed
func (m *MonitoringTools) CloseAlert(alertID string, alerts []*Alert) bool {
	for _, alert := range alerts {
		if alert.ID == alertID {
			alert.Status = "closed"
			return true
		}
	}
	return false
}

// GenerateMetricsReport generates a metrics report
func (m *MonitoringTools) GenerateMetricsReport(metrics []SystemMetrics) string {
	var report strings.Builder
	
	report.WriteString("=== System Metrics Report ===\n")
	report.WriteString(fmt.Sprintf("Generated: %s\n", time.Now().Format(time.RFC3339)))
	report.WriteString(fmt.Sprintf("Total Samples: %d\n\n", len(metrics)))
	
	if len(metrics) == 0 {
		report.WriteString("No metrics available\n")
		return report.String()
	}
	
	// Calculate averages
	var totalCPU, totalMemory, totalDisk float64
	for _, m := range metrics {
		totalCPU += m.CPUUsage
		totalMemory += m.MemoryUsage
		totalDisk += m.DiskUsage
	}
	
	count := float64(len(metrics))
	report.WriteString(fmt.Sprintf("Average CPU Usage: %.2f%%\n", totalCPU/count))
	report.WriteString(fmt.Sprintf("Average Memory Usage: %.2f%%\n", totalMemory/count))
	report.WriteString(fmt.Sprintf("Average Disk Usage: %.2f%%\n", totalDisk/count))
	
	// Peak values
	var maxCPU, maxMemory, maxDisk float64
	for _, m := range metrics {
		if m.CPUUsage > maxCPU {
			maxCPU = m.CPUUsage
		}
		if m.MemoryUsage > maxMemory {
			maxMemory = m.MemoryUsage
		}
		if m.DiskUsage > maxDisk {
			maxDisk = m.DiskUsage
		}
	}
	
	report.WriteString("\n")
	report.WriteString(fmt.Sprintf("Peak CPU Usage: %.2f%%\n", maxCPU))
	report.WriteString(fmt.Sprintf("Peak Memory Usage: %.2f%%\n", maxMemory))
	report.WriteString(fmt.Sprintf("Peak Disk Usage: %.2f%%\n", maxDisk))
	
	report.WriteString("\n=== End of Report ===\n")
	
	return report.String()
}

// CalculateSystemHealth calculates overall system health score
func (m *MonitoringTools) CalculateSystemHealth(metrics SystemMetrics) (float64, string) {
	score := 100.0
	
	// Deduct for high resource usage
	if metrics.CPUUsage > 80 {
		score -= 20
	} else if metrics.CPUUsage > 60 {
		score -= 10
	}
	
	if metrics.MemoryUsage > 90 {
		score -= 25
	} else if metrics.MemoryUsage > 70 {
		score -= 15
	}
	
	if metrics.DiskUsage > 90 {
		score -= 20
	} else if metrics.DiskUsage > 80 {
		score -= 10
	}
	
	var status string
	switch {
	case score >= 90:
		status = "Excellent"
	case score >= 75:
		status = "Good"
	case score >= 60:
		status = "Fair"
	case score >= 40:
		status = "Poor"
	default:
		status = "Critical"
	}
	
	return score, status
}

// DetectAnomalousActivity detects anomalous system activity
func (m *MonitoringTools) DetectAnomalousActivity(metrics []SystemMetrics) []string {
	var anomalies []string
	
	if len(metrics) < 2 {
		return anomalies
	}
	
	// Calculate baseline
	var avgCPU, avgMemory float64
	for _, m := range metrics {
		avgCPU += m.CPUUsage
		avgMemory += m.MemoryUsage
	}
	avgCPU /= float64(len(metrics))
	avgMemory /= float64(len(metrics))
	
	// Check for sudden spikes
	for i := 1; i < len(metrics); i++ {
		cpuDiff := metrics[i].CPUUsage - metrics[i-1].CPUUsage
		memDiff := metrics[i].MemoryUsage - metrics[i-1].MemoryUsage
		
		if cpuDiff > 30 {
			anomalies = append(anomalies, fmt.Sprintf("Sudden CPU spike detected at %s", metrics[i].Timestamp.Format(time.RFC3339)))
		}
		
		if memDiff > 25 {
			anomalies = append(anomalies, fmt.Sprintf("Sudden memory increase detected at %s", metrics[i].Timestamp.Format(time.RFC3339)))
		}
	}
	
	// Check for sustained high usage
	highCPUCount := 0
	for _, m := range metrics {
		if m.CPUUsage > 90 {
			highCPUCount++
		}
	}
	
	if highCPUCount > len(metrics)/2 {
		anomalies = append(anomalies, "Sustained high CPU usage detected")
	}
	
	return anomalies
}

// ExportLogsToCSV exports logs to CSV format
func (m *MonitoringTools) ExportLogsToCSV(logs []*LogEntry) string {
	var csv strings.Builder
	
	// Header
	csv.WriteString("Timestamp,Level,Source,Message,TraceID\n")
	
	// Data
	for _, log := range logs {
		csv.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s\n",
			log.Timestamp,
			log.Level,
			log.Source,
			strings.ReplaceAll(log.Message, ",", ";"),
			log.TraceID,
		))
	}
	
	return csv.String()
}

// GenerateHealthReport generates a system health report
func (m *MonitoringTools) GenerateHealthReport(metrics SystemMetrics, alerts []*Alert) string {
	var report strings.Builder
	
	report.WriteString("=== System Health Report ===\n")
	report.WriteString(fmt.Sprintf("Generated: %s\n\n", time.Now().Format(time.RFC3339)))
	
	score, status := m.CalculateSystemHealth(metrics)
	report.WriteString(fmt.Sprintf("Health Score: %.1f/100\n", score))
	report.WriteString(fmt.Sprintf("Health Status: %s\n\n", status))
	
	report.WriteString("Current Metrics:\n")
	report.WriteString(fmt.Sprintf("  CPU Usage: %.2f%%\n", metrics.CPUUsage))
	report.WriteString(fmt.Sprintf("  Memory Usage: %.2f%%\n", metrics.MemoryUsage))
	report.WriteString(fmt.Sprintf("  Disk Usage: %.2f%%\n", metrics.DiskUsage))
	report.WriteString(fmt.Sprintf("  Active Sessions: %d\n", metrics.ActiveSessions))
	
	// Alert summary
	openAlerts := 0
	for _, alert := range alerts {
		if alert.Status == "open" {
			openAlerts++
		}
	}
	
	report.WriteString("\n")
	report.WriteString(fmt.Sprintf("Total Alerts: %d\n", len(alerts)))
	report.WriteString(fmt.Sprintf("Open Alerts: %d\n", openAlerts))
	
	if openAlerts > 0 {
		report.WriteString("\nRecent Open Alerts:\n")
		count := 0
		for _, alert := range alerts {
			if alert.Status == "open" && count < 5 {
				report.WriteString(fmt.Sprintf("  [%s] %s: %s\n", 
					alert.Severity, alert.Type, alert.Title))
				count++
			}
		}
	}
	
	report.WriteString("\n=== End of Report ===\n")
	
	return report.String()
}

// RotateLogs rotates log files
func (m *MonitoringTools) RotateLogs(filename string, maxSizeMB int) error {
	info, err := os.Stat(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	
	sizeMB := info.Size() / (1024 * 1024)
	if sizeMB < int64(maxSizeMB) {
		return nil
	}
	
	// Rotate the file
	backupName := fmt.Sprintf("%s.%s", filename, time.Now().Format("20060102-150405"))
	return os.Rename(filename, backupName)
}

// DisplayMonitoringTools shows available monitoring tools
func DisplayMonitoringTools() {
	fmt.Println("\n=== Monitoring & Logging Tools ===")
	fmt.Println("1. Create Log Entry")
	fmt.Println("2. Analyze Logs")
	fmt.Println("3. Create Alert")
	fmt.Println("4. Generate Health Report")
	fmt.Println("5. Detect Anomalies")
}
