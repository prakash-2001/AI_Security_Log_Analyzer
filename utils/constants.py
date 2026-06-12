"""
Utility constants: sample logs, severity mappings, thresholds.
"""

SAMPLE_LOGS = """192.168.1.105 - - [07/Jun/2026:02:14:33 +0000] "POST /admin/login HTTP/1.1" 401 512
192.168.1.105 - - [07/Jun/2026:02:14:35 +0000] "POST /admin/login HTTP/1.1" 401 512
192.168.1.105 - - [07/Jun/2026:02:14:37 +0000] "POST /admin/login HTTP/1.1" 401 512
192.168.1.105 - - [07/Jun/2026:02:14:39 +0000] "POST /admin/login HTTP/1.1" 401 512
192.168.1.105 - - [07/Jun/2026:02:14:41 +0000] "POST /admin/login HTTP/1.1" 401 512
192.168.1.105 - - [07/Jun/2026:02:14:43 +0000] "POST /admin/login HTTP/1.1" 401 512
192.168.1.105 - - [07/Jun/2026:02:14:45 +0000] "POST /admin/login HTTP/1.1" 200 1024
10.0.0.88 - - [07/Jun/2026:03:45:12 +0000] "GET /api/users HTTP/1.1" 200 8192
10.0.0.88 - - [07/Jun/2026:03:45:13 +0000] "GET /api/users?page=2 HTTP/1.1" 200 8192
10.0.0.88 - - [07/Jun/2026:03:45:14 +0000] "GET /api/orders HTTP/1.1" 200 16384
10.0.0.88 - - [07/Jun/2026:03:45:15 +0000] "GET /api/payments HTTP/1.1" 200 32768
10.0.0.88 - - [07/Jun/2026:03:45:16 +0000] "GET /api/transactions HTTP/1.1" 200 65536
10.0.0.88 - - [07/Jun/2026:03:45:17 +0000] "GET /api/reports HTTP/1.1" 200 131072
203.0.113.42 - - [07/Jun/2026:09:12:05 +0000] "GET /index.html HTTP/1.1" 200 1024
203.0.113.42 - - [07/Jun/2026:09:12:06 +0000] "GET /about.html HTTP/1.1" 200 2048
172.16.0.55 - - [07/Jun/2026:01:30:00 +0000] "GET /admin/dashboard HTTP/1.1" 200 4096
172.16.0.55 - - [07/Jun/2026:01:30:01 +0000] "GET /admin/users HTTP/1.1" 200 8192
172.16.0.55 - - [07/Jun/2026:01:30:02 +0000] "DELETE /admin/users/42 HTTP/1.1" 204 0
198.51.100.7 - - [07/Jun/2026:14:22:18 +0000] "GET /login HTTP/1.1" 200 512
198.51.100.7 - - [07/Jun/2026:14:22:19 +0000] "POST /login HTTP/1.1" 302 0
192.168.2.200 - - [07/Jun/2026:04:00:01 +0000] "GET /etc/passwd HTTP/1.1" 404 256
192.168.2.200 - - [07/Jun/2026:04:00:02 +0000] "GET /../../../etc/shadow HTTP/1.1" 400 256
192.168.2.200 - - [07/Jun/2026:04:00:03 +0000] "GET /wp-admin/install.php HTTP/1.1" 404 256
Jun  7 02:14:33 webserver sshd[1234]: Failed password for root from 192.168.1.105 port 22 ssh2
Jun  7 02:14:35 webserver sshd[1234]: Failed password for root from 192.168.1.105 port 22 ssh2
Jun  7 02:14:37 webserver sshd[1234]: Failed password for admin from 192.168.1.105 port 22 ssh2
Jun  7 10:05:12 webserver sshd[5678]: Accepted publickey for deploy from 10.0.0.10 port 22 ssh2
Jun  7 02:14:43 webserver sshd[1234]: Failed password for root from 192.168.1.105 port 22 ssh2
"""

SEVERITY_COLORS = {
    "CRITICAL": "#FF3B30",
    "HIGH":     "#FF9500",
    "MEDIUM":   "#FFCC00",
    "LOW":      "#34C759",
    "INFO":     "#007AFF",
}

THREAT_ICONS = {
    "brute_force":          "🔨",
    "data_exfiltration":    "📤",
    "privilege_escalation": "⬆️",
    "path_traversal":       "🗂️",
    "credential_stuffing":  "🔑",
    "port_scan":            "🔍",
    "unknown":              "⚠️",
}

DEFAULT_THRESHOLD = 55
MAX_ANOMALIES_FOR_AI = 15   # Keep Groq prompt concise
