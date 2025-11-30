#!/usr/bin/env python3
"""
DeepRecon - Team 313 IQ
Advanced OSINT and Security Reconnaissance Tool
Usage: python deeprecon.py --target <domain_or_ip> [options]
"""

import argparse
import sys
import json
from datetime import datetime

from utils import (
    print_banner, print_header, print_warning, print_success, 
    print_info, is_ip_or_domain
)
from dns_recon import DNSRecon
from http_recon import HTTPRecon
from ssl_recon import SSLRecon
from whois_recon import WhoisRecon
from port_scanner import PortScanner
from security_checks import SecurityChecks


class DeepRecon:
    """Main reconnaissance orchestrator"""
    
    def __init__(self, target, options=None):
        self.target = target
        self.options = options or {}
        self.results = {
            'target': target,
            'scan_time': datetime.now().isoformat(),
            'modules': {}
        }
    
    def run_dns_recon(self):
        """Run DNS reconnaissance"""
        try:
            print_header("DNS Reconnaissance")
            dns = DNSRecon(self.target)
            results = dns.run_all()
            self.results['modules']['dns'] = results
            print_success("DNS reconnaissance completed")
        except Exception as e:
            print_warning(f"DNS reconnaissance failed: {str(e)}")
    
    def run_whois_recon(self):
        """Run WHOIS reconnaissance"""
        try:
            print_header("WHOIS Information")
            whois = WhoisRecon(self.target)
            results = whois.run_all()
            self.results['modules']['whois'] = results
            print_success("WHOIS reconnaissance completed")
        except Exception as e:
            print_warning(f"WHOIS reconnaissance failed: {str(e)}")
    
    def run_http_recon(self):
        """Run HTTP reconnaissance"""
        try:
            print_header("HTTP Reconnaissance")
            http = HTTPRecon(self.target)
            results = http.run_all()
            self.results['modules']['http'] = results
            print_success("HTTP reconnaissance completed")
        except Exception as e:
            print_warning(f"HTTP reconnaissance failed: {str(e)}")
    
    def run_ssl_recon(self):
        """Run SSL/TLS reconnaissance"""
        try:
            print_header("SSL/TLS Analysis")
            ssl = SSLRecon(self.target)
            results = ssl.run_all()
            self.results['modules']['ssl'] = results
            print_success("SSL reconnaissance completed")
        except Exception as e:
            print_warning(f"SSL reconnaissance failed: {str(e)}")
    
    def run_port_scan(self):
        """Run port scanning"""
        try:
            print_header("Port Scanning")
            scanner = PortScanner(self.target)
            results = scanner.run_all()
            self.results['modules']['ports'] = {'open_ports': results}
            print_success("Port scanning completed")
        except Exception as e:
            print_warning(f"Port scanning failed: {str(e)}")
    
    def run_security_checks(self):
        """Run security checks"""
        try:
            print_header("Security Vulnerability Assessment")
            
            # Get banner from HTTP results
            banner = self.results.get('modules', {}).get('http', {}).get('server', 'Unknown')
            headers = self.results.get('modules', {}).get('http', {}).get('headers', {})
            
            security = SecurityChecks(self.target)
            results = security.run_all(banner, headers=headers)
            self.results['modules']['security'] = results
            print_success("Security checks completed")
        except Exception as e:
            print_warning(f"Security checks failed: {str(e)}")
    
    def run_full_scan(self):
        """Run all reconnaissance modules"""
        print_banner()
        print_info(f"Starting comprehensive reconnaissance on: {self.target}")
        print_info(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        self.run_dns_recon()
        self.run_whois_recon()
        self.run_http_recon()
        self.run_ssl_recon()
        self.run_port_scan()
        self.run_security_checks()
        
        print_header("Scan Summary")
        print_success("Reconnaissance completed successfully!")
    
    def save_results(self, filename):
        """Save results to JSON file"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            print_success(f"Results saved to {filename}")
        except Exception as e:
            print_warning(f"Failed to save results: {str(e)}")
    
    def get_results(self):
        """Get results dictionary"""
        return self.results


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='DeepRecon - Team 313 IQ OSINT & Security Reconnaissance Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python deeprecon.py --target example.com
  python deeprecon.py --target 192.168.1.1 --dns --http --ports
  python deeprecon.py --target example.com --save results.json
        '''
    )
    
    # Main arguments
    parser.add_argument('--target', '-t', required=True, 
                        help='Target domain or IP address')
    
    # Module selection
    parser.add_argument('--dns', action='store_true',
                        help='Run DNS reconnaissance only')
    parser.add_argument('--whois', action='store_true',
                        help='Run WHOIS lookup only')
    parser.add_argument('--http', action='store_true',
                        help='Run HTTP reconnaissance only')
    parser.add_argument('--ssl', action='store_true',
                        help='Run SSL analysis only')
    parser.add_argument('--ports', '-p', action='store_true',
                        help='Run port scanning only')
    parser.add_argument('--security', '-s', action='store_true',
                        help='Run security checks only')
    
    # Options
    parser.add_argument('--save', '-o', 
                        help='Save results to JSON file')
    parser.add_argument('--version', '-v', action='version', 
                        version='DeepRecon v1.0.0 - Team 313 IQ')
    
    args = parser.parse_args()
    
    # Validate target
    target_type = is_ip_or_domain(args.target)
    if not target_type:
        print_warning("Invalid target. Please provide a valid domain or IP address.")
        sys.exit(1)
    
    print_info(f"Target type detected: {target_type}")
    
    # Create reconnaissance object
    recon = DeepRecon(args.target)
    
    # Check if specific modules were requested
    has_specific_module = any([args.dns, args.whois, args.http, args.ssl, args.ports, args.security])
    
    if has_specific_module:
        # Run only specified modules
        print_banner()
        
        if args.dns:
            recon.run_dns_recon()
        if args.whois:
            recon.run_whois_recon()
        if args.http:
            recon.run_http_recon()
        if args.ssl:
            recon.run_ssl_recon()
        if args.ports:
            recon.run_port_scan()
        if args.security:
            recon.run_security_checks()
    else:
        # Run full scan
        recon.run_full_scan()
    
    # Save results if requested
    if args.save:
        recon.save_results(args.save)
    
    print_success("\n✓ All operations completed!")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print_warning("\n\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print_warning(f"\n[!] An error occurred: {str(e)}")
        sys.exit(1)
