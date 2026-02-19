"""
Security Monitoring Configuration for VRCBin

This module provides configuration and utilities for monitoring and responding to
suspicious requests and potential security threats.
"""

import os
from datetime import datetime, timedelta
from collections import defaultdict, deque
from threading import Lock

# Configuration
SECURITY_CONFIG = {
    # Enable/disable security monitoring
    'ENABLE_MONITORING': True,
    
    # Log suspicious requests to file
    'LOG_TO_FILE': True,
    'LOG_FILE_PATH': 'logs/security.log',
    
    # Rate limiting for suspicious IPs
    'ENABLE_IP_RATE_LIMITING': True,
    'MAX_SUSPICIOUS_REQUESTS_PER_HOUR': 10,
    'SUSPICIOUS_REQUEST_WINDOW': 3600,  # 1 hour in seconds
    
    # Block suspicious IPs temporarily
    'ENABLE_IP_BLOCKING': False,  # Set to True to enable automatic blocking
    'BLOCK_DURATION_HOURS': 24,
    'MAX_SUSPICIOUS_REQUESTS_BEFORE_BLOCK': 20,
    
    # Suspicious patterns to monitor
    'SUSPICIOUS_PATTERNS': [
        # PHP vulnerabilities
        '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
        '/eval-stdin.php',
        '/shell.php',
        '/cmd.php',
        '/phpinfo.php',
        '/info.php',
        '/test.php',
        '/debug.php',
        '/console.php',
        
        # Common admin panels
        '/wp-admin/',
        '/phpmyadmin/',
        '/admin/',
        '/administrator/',
        '/manage/',
        '/management/',
        
        # Configuration files
        '/.env',
        '/config.php',
        '/config.ini',
        '/config.json',
        '/wp-config.php',
        '/configuration.php',
        
        # Development files
        '/vendor/',
        '/node_modules/',
        '/.git/',
        '/.svn/',
        '/.hg/',
        '/.bzr/',
        
        # Backup files
        '/backup/',
        '/backups/',
        '/bak/',
        '/old/',
        '/archive/',
        
        # Database files
        '/db/',
        '/database/',
        '/sql/',
        '/mysql/',
        '/postgresql/',
        '/sqlite/',
        
        # Shell/command execution
        '/shell',
        '/cmd',
        '/exec',
        '/system',
        '/eval',
        '/assert',
        '/passthru',
        '/base64_decode',
        '/gzinflate',
        '/str_rot13',
        '/gzuncompress',
        '/gzdecode',
        '/gzfile',
        '/readfile',
        '/file_get_contents',
        '/file_put_contents',
        '/fopen',
        '/fwrite',
        '/fread',
        '/include',
        '/require',
        '/include_once',
        '/require_once'
    ],
    
    # Suspicious user agents
    'SUSPICIOUS_USER_AGENTS': [
        # Security testing tools
        'sqlmap', 'nikto', 'nmap', 'acunetix', 'burp', 'zap', 'w3af',
        'nessus', 'openvas', 'metasploit', 'beef', 'cobalt', 'havij',
        'pangolin', 'sqlsus', 'sqlninja', 'absinthe', 'bsqlbf',
        'jsql', 'sqlpower', 'sqldict', 'oscanner',
        
        # Web application scanners
        'webscarab', 'paros', 'arachni', 'skipfish', 'grendel',
        'websecurify', 'netsparker', 'appscan',
        
        # Generic suspicious patterns
        'bot', 'crawler', 'spider', 'scanner', 'probe', 'test',
        'hack', 'exploit', 'vulnerability', 'security'
    ]
}

class SecurityMonitor:
    """Monitor and track suspicious requests"""
    
    def __init__(self):
        self.ip_requests = defaultdict(lambda: deque(maxlen=100))
        self.blocked_ips = {}
        self.lock = Lock()
        
        # Ensure log directory exists
        if SECURITY_CONFIG['LOG_TO_FILE']:
            log_dir = os.path.dirname(SECURITY_CONFIG['LOG_FILE_PATH'])
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir)
    
    def is_suspicious_request(self, path, user_agent):
        """Check if a request is suspicious"""
        path_lower = path.lower()
        user_agent_lower = user_agent.lower()
        
        # Check suspicious patterns
        for pattern in SECURITY_CONFIG['SUSPICIOUS_PATTERNS']:
            if pattern in path_lower:
                return True, f"Pattern match: {pattern}"
        
        # Check suspicious user agents
        for agent in SECURITY_CONFIG['SUSPICIOUS_USER_AGENTS']:
            if agent in user_agent_lower:
                return True, f"User agent match: {agent}"
        
        return False, None
    
    def log_suspicious_request(self, ip, path, user_agent, status_code, reason):
        """Log a suspicious request"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[SUSPICIOUS] {timestamp} - IP: {ip} - Path: {path} - UA: {user_agent} - Status: {status_code} - Reason: {reason}"
        
        print(log_entry)
        
        if SECURITY_CONFIG['LOG_TO_FILE']:
            try:
                with open(SECURITY_CONFIG['LOG_FILE_PATH'], 'a', encoding='utf-8') as f:
                    f.write(log_entry + '\n')
            except Exception as e:
                print(f"Error writing to log file: {e}")
    
    def track_ip_request(self, ip):
        """Track requests from an IP address"""
        if not SECURITY_CONFIG['ENABLE_IP_RATE_LIMITING']:
            return True
        
        with self.lock:
            now = datetime.now()
            self.ip_requests[ip].append(now)
            
            # Remove old requests outside the window
            window_start = now - timedelta(seconds=SECURITY_CONFIG['SUSPICIOUS_REQUEST_WINDOW'])
            while self.ip_requests[ip] and self.ip_requests[ip][0] < window_start:
                self.ip_requests[ip].popleft()
            
            # Check if IP should be blocked
            if len(self.ip_requests[ip]) >= SECURITY_CONFIG['MAX_SUSPICIOUS_REQUESTS_BEFORE_BLOCK']:
                if SECURITY_CONFIG['ENABLE_IP_BLOCKING']:
                    self.blocked_ips[ip] = now + timedelta(hours=SECURITY_CONFIG['BLOCK_DURATION_HOURS'])
                    print(f"[BLOCKED] IP {ip} blocked for {SECURITY_CONFIG['BLOCK_DURATION_HOURS']} hours")
            
            return len(self.ip_requests[ip]) < SECURITY_CONFIG['MAX_SUSPICIOUS_REQUESTS_PER_HOUR']
    
    def is_ip_blocked(self, ip):
        """Check if an IP is currently blocked"""
        if not SECURITY_CONFIG['ENABLE_IP_BLOCKING']:
            return False
        
        with self.lock:
            if ip in self.blocked_ips:
                if datetime.now() < self.blocked_ips[ip]:
                    return True
                else:
                    # Remove expired block
                    del self.blocked_ips[ip]
            return False
    
    def get_ip_stats(self, ip):
        """Get statistics for an IP address"""
        with self.lock:
            return {
                'total_requests': len(self.ip_requests[ip]),
                'is_blocked': self.is_ip_blocked(ip),
                'block_expires': self.blocked_ips.get(ip)
            }

# Global security monitor instance
security_monitor = SecurityMonitor()

def check_request_security(request, response_status):
    """Main function to check request security"""
    if not SECURITY_CONFIG['ENABLE_MONITORING']:
        return
    
    ip = request.remote_addr
    path = request.path
    user_agent = request.headers.get('User-Agent', '')
    
    # Check if IP is blocked
    if security_monitor.is_ip_blocked(ip):
        print(f"[BLOCKED] Blocked IP {ip} attempted to access {path}")
        return
    
    # Check if request is suspicious
    is_suspicious, reason = security_monitor.is_suspicious_request(path, user_agent)
    
    if is_suspicious:
        # Log the suspicious request
        security_monitor.log_suspicious_request(ip, path, user_agent, response_status, reason)
        
        # Track the IP request
        if not security_monitor.track_ip_request(ip):
            print(f"[RATE_LIMIT] IP {ip} exceeded suspicious request limit") 