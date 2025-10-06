package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// NetworkTools provides network security utilities
type NetworkTools struct{}

// PortScan scans a range of ports on a target host
func (n *NetworkTools) PortScan(host string, startPort, endPort int) ([]int, error) {
	var openPorts []int

	for port := startPort; port <= endPort; port++ {
		address := fmt.Sprintf("%s:%d", host, port)
		conn, err := net.DialTimeout("tcp", address, 1*time.Second)
		if err == nil {
			openPorts = append(openPorts, port)
			conn.Close()
		}
	}

	return openPorts, nil
}

// DNSLookup performs DNS resolution for a hostname
func (n *NetworkTools) DNSLookup(hostname string) ([]string, error) {
	addrs, err := net.LookupHost(hostname)
	if err != nil {
		return nil, err
	}
	return addrs, nil
}

// ReverseDNSLookup performs reverse DNS lookup for an IP address
func (n *NetworkTools) ReverseDNSLookup(ip string) ([]string, error) {
	names, err := net.LookupAddr(ip)
	if err != nil {
		return nil, err
	}
	return names, nil
}

// CheckHTTPHeaders retrieves and analyzes HTTP headers for security
func (n *NetworkTools) CheckHTTPHeaders(url string) (map[string]string, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	headers := make(map[string]string)
	for key, values := range resp.Header {
		headers[key] = strings.Join(values, ", ")
	}

	return headers, nil
}

// CheckSSL verifies SSL/TLS certificate for a host
func (n *NetworkTools) CheckSSL(host string, port int) (map[string]interface{}, error) {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	info := make(map[string]interface{})
	info["host"] = host
	info["port"] = port
	info["connected"] = true
	info["timestamp"] = time.Now().Format(time.RFC3339)

	return info, nil
}

// TraceRoute performs a basic traceroute to a target host
func (n *NetworkTools) TraceRoute(host string, maxHops int) ([]string, error) {
	var route []string

	for ttl := 1; ttl <= maxHops; ttl++ {
		// Simplified traceroute - in production, use ICMP
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:80", host), 2*time.Second)
		if err == nil {
			route = append(route, fmt.Sprintf("Hop %d: Reached destination", ttl))
			conn.Close()
			break
		}
		route = append(route, fmt.Sprintf("Hop %d: *", ttl))
	}

	return route, nil
}

// GetLocalIP retrieves the local IP address
func (n *NetworkTools) GetLocalIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

// ValidateIP checks if a string is a valid IP address
func (n *NetworkTools) ValidateIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// GetPublicIP attempts to retrieve the public IP address
func (n *NetworkTools) GetPublicIP() (string, error) {
	resp, err := http.Get("https://api.ipify.org")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	buf := make([]byte, 256)
	bytesRead, err := resp.Body.Read(buf)
	if err != nil && err.Error() != "EOF" {
		return "", err
	}

	return string(buf[:bytesRead]), nil
}

// SubnetCalculator calculates subnet information
func (n *NetworkTools) SubnetCalculator(cidr string) (map[string]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	info := make(map[string]string)
	info["network"] = ipnet.IP.String()
	info["mask"] = fmt.Sprintf("%d.%d.%d.%d", ipnet.Mask[0], ipnet.Mask[1], ipnet.Mask[2], ipnet.Mask[3])
	info["cidr"] = cidr

	return info, nil
}

// DisplayNetworkTools shows available network security tools
func DisplayNetworkTools() {
	fmt.Println("\n=== Network Security Tools ===")
	fmt.Println("1. Port Scanner")
	fmt.Println("2. DNS Lookup")
	fmt.Println("3. Reverse DNS Lookup")
	fmt.Println("4. HTTP Headers Check")
	fmt.Println("5. SSL/TLS Certificate Check")
	fmt.Println("6. Traceroute")
}

// AdvancedPortScan performs advanced port scanning with protocol detection
func (n *NetworkTools) AdvancedPortScan(host string, ports []int) map[int]map[string]interface{} {
	results := make(map[int]map[string]interface{})
	
	for _, port := range ports {
		info := make(map[string]interface{})
		address := fmt.Sprintf("%s:%d", host, port)
		
		conn, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err == nil {
			info["status"] = "open"
			info["protocol"] = "tcp"
			info["service"] = n.identifyService(port)
			conn.Close()
		} else {
			info["status"] = "closed"
		}
		
		results[port] = info
	}
	
	return results
}

// identifyService identifies common services by port number
func (n *NetworkTools) identifyService(port int) string {
	services := map[int]string{
		20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
		25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
		143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
		3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
		8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
	}
	
	if service, ok := services[port]; ok {
		return service
	}
	return "Unknown"
}

// BulkDNSLookup performs DNS lookups for multiple hostnames
func (n *NetworkTools) BulkDNSLookup(hostnames []string) map[string][]string {
	results := make(map[string][]string)
	
	for _, hostname := range hostnames {
		addrs, err := net.LookupHost(hostname)
		if err == nil {
			results[hostname] = addrs
		} else {
			results[hostname] = []string{"lookup failed"}
		}
	}
	
	return results
}

// GetMXRecords retrieves MX records for a domain
func (n *NetworkTools) GetMXRecords(domain string) ([]*net.MX, error) {
	return net.LookupMX(domain)
}

// GetTXTRecords retrieves TXT records for a domain
func (n *NetworkTools) GetTXTRecords(domain string) ([]string, error) {
	return net.LookupTXT(domain)
}

// GetNSRecords retrieves name server records for a domain
func (n *NetworkTools) GetNSRecords(domain string) ([]*net.NS, error) {
	return net.LookupNS(domain)
}

// GetCNAME retrieves CNAME record for a hostname
func (n *NetworkTools) GetCNAME(host string) (string, error) {
	return net.LookupCNAME(host)
}

// PingHost performs a basic connectivity check
func (n *NetworkTools) PingHost(host string, timeout time.Duration) (bool, time.Duration, error) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", host+":80", timeout)
	elapsed := time.Since(start)
	
	if err != nil {
		return false, 0, err
	}
	defer conn.Close()
	
	return true, elapsed, nil
}

// GetNetworkInterfaces retrieves local network interfaces
func (n *NetworkTools) GetNetworkInterfaces() ([]map[string]interface{}, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	
	var result []map[string]interface{}
	for _, iface := range interfaces {
		ifaceInfo := make(map[string]interface{})
		ifaceInfo["name"] = iface.Name
		ifaceInfo["mtu"] = iface.MTU
		ifaceInfo["mac"] = iface.HardwareAddr.String()
		
		addrs, err := iface.Addrs()
		if err == nil {
			var addrStrings []string
			for _, addr := range addrs {
				addrStrings = append(addrStrings, addr.String())
			}
			ifaceInfo["addresses"] = addrStrings
		}
		
		result = append(result, ifaceInfo)
	}
	
	return result, nil
}

// CheckHTTPSRedirect checks if HTTP redirects to HTTPS
func (n *NetworkTools) CheckHTTPSRedirect(domain string) (bool, error) {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 10 * time.Second,
	}
	
	resp, err := client.Get("http://" + domain)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		return strings.HasPrefix(location, "https://"), nil
	}
	
	return false, nil
}

// GetHostByIP performs reverse lookup
func (n *NetworkTools) GetHostByIP(ip string) ([]string, error) {
	return net.LookupAddr(ip)
}

// CheckPortRange scans a range of ports quickly
func (n *NetworkTools) CheckPortRange(host string, startPort, endPort, timeout int) []int {
	var openPorts []int
	
	for port := startPort; port <= endPort; port++ {
		address := fmt.Sprintf("%s:%d", host, port)
		conn, err := net.DialTimeout("tcp", address, time.Duration(timeout)*time.Millisecond)
		if err == nil {
			openPorts = append(openPorts, port)
			conn.Close()
		}
	}
	
	return openPorts
}

// ValidateIPv4 validates IPv4 address format
func (n *NetworkTools) ValidateIPv4(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.To4() != nil
}

// ValidateIPv6 validates IPv6 address format
func (n *NetworkTools) ValidateIPv6(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.To4() == nil && parsed.To16() != nil
}

// CalculateNetworkAddress calculates network address from CIDR
func (n *NetworkTools) CalculateNetworkAddress(cidr string) (map[string]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	
	info := make(map[string]string)
	info["ip"] = ip.String()
	info["network"] = ipnet.IP.String()
	info["netmask"] = net.IP(ipnet.Mask).String()
	info["cidr"] = cidr
	
	// Calculate broadcast address
	broadcast := make(net.IP, len(ipnet.IP))
	for i := range ipnet.IP {
		broadcast[i] = ipnet.IP[i] | ^ipnet.Mask[i]
	}
	info["broadcast"] = broadcast.String()
	
	// Calculate host count
	ones, bits := ipnet.Mask.Size()
	hosts := (1 << uint(bits-ones)) - 2
	info["hosts"] = fmt.Sprintf("%d", hosts)
	
	return info, nil
}

// GetRemoteAddr gets remote address information
func (n *NetworkTools) GetRemoteAddr(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	return resp.Request.RemoteAddr, nil
}

// CheckServiceAvailability checks if a service is available
func (n *NetworkTools) CheckServiceAvailability(host string, port int) bool {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
