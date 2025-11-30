"""
Port Scanning Module - Fast basic port scan
"""
import socket
import threading
from queue import Queue
from utils import print_section, print_result, print_success, print_warning


class PortScanner:
    """Basic port scanner"""
    
    # Common ports to scan
    COMMON_PORTS = [
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        53,    # DNS
        80,    # HTTP
        110,   # POP3
        143,   # IMAP
        443,   # HTTPS
        445,   # SMB
        465,   # SMTPS
        587,   # SMTP
        993,   # IMAPS
        995,   # POP3S
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        5900,  # VNC
        8080,  # HTTP Alt
        8443,  # HTTPS Alt
        8888,  # HTTP Alt
        9200,  # Elasticsearch
    ]
    
    def __init__(self, target):
        self.target = target
        self.results = {}
        self.open_ports = []
        self.lock = threading.Lock()
    
    def _check_port(self, port):
        """Check if a port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                with self.lock:
                    self.open_ports.append(port)
                    print_success(f"Port {port} is OPEN")
        except socket.gaierror:
            print_warning("Hostname could not be resolved")
            return
        except socket.error:
            pass
    
    def get_service_name(self, port):
        """Get service name for port"""
        try:
            return socket.getservbyport(port)
        except:
            return "Unknown"
    
    def scan(self, ports=None, threads=20):
        """Scan ports with threading"""
        try:
            print_section("Port Scanning")
            
            ports_to_scan = ports or self.COMMON_PORTS
            print_result("Target", self.target)
            print_result("Ports to scan", f"{len(ports_to_scan)} ports")
            print_warning("Scanning in progress...")
            
            # Create thread pool
            thread_list = []
            
            for port in ports_to_scan:
                thread = threading.Thread(target=self._check_port, args=(port,))
                thread.daemon = True
                thread.start()
                thread_list.append(thread)
                
                # Limit concurrent threads
                if len(thread_list) >= threads:
                    for t in thread_list:
                        t.join()
                    thread_list = []
            
            # Wait for remaining threads
            for t in thread_list:
                t.join()
            
            print_result("Scan complete", f"Found {len(self.open_ports)} open ports")
            
            # Get service names
            if self.open_ports:
                print("\nOpen ports and services:")
                for port in sorted(self.open_ports):
                    service = self.get_service_name(port)
                    print_success(f"  {port}/tcp - {service}")
            
            self.results['open_ports'] = self.open_ports
            return self.open_ports
        except Exception as e:
            print_warning(f"Port scan failed: {str(e)}")
            return []
    
    def run_all(self):
        """Run port scanning"""
        return self.scan()
