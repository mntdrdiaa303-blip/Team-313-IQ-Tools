"""
Security Checks Module - XSS, SQLi, LFI, CVE detection
"""
import requests
import re
from utils import print_section, print_result, print_warning, print_success, print_danger


class SecurityChecks:
    """Security vulnerability checks"""
    
    # Known CVE database (basic signatures)
    CVE_DATABASE = {
        'Apache': {
            'Struts': {'versions': ['1.0-2.5.0'], 'cve': 'CVE-2017-5645'},
            'Log4j': {'versions': ['2.0-2.14.1'], 'cve': 'CVE-2021-44228'},
        },
        'nginx': {
            '1.16.0-1.17.7': {'cve': 'CVE-2019-20372'},
        },
        'php': {
            '7.0.0-7.4.26': {'cve': 'CVE-2021-21219'},
        },
        'IIS': {
            '8.5': {'cve': 'CVE-2021-26855'},
            '10.0': {'cve': 'CVE-2021-34527'},
        }
    }
    
    # Payload samples for detection (for testing purposes)
    TEST_PAYLOADS = {
        'xss': ["<script>alert('xss')</script>", "';><script>alert('xss')</script>"],
        'sqli': ["' OR '1'='1", "1' UNION SELECT NULL--", "admin' --", "1' AND '1'='1"],
        'lfi': ["../../../etc/passwd", ".../.../.../.../etc/passwd", "../../../../../../windows/win.ini"],
    }
    
    def __init__(self, target):
        self.target = target
        self.results = {}
        self.vulnerabilities = []
    
    def check_banner_for_cves(self, banner):
        """Check server banner against known CVEs"""
        try:
            print_section("CVE Banner Analysis")
            
            banner_lower = banner.lower()
            found_vulnerabilities = []
            
            # Check for Apache vulnerabilities
            if 'apache' in banner_lower:
                if 'struts' in banner_lower:
                    print_danger("Potentially vulnerable to CVE-2017-5645 (Apache Struts)")
                    found_vulnerabilities.append('CVE-2017-5645')
            
            # Check for Nginx vulnerabilities
            if 'nginx' in banner_lower:
                if '1.16.0' in banner or '1.17' in banner:
                    print_danger("Potentially vulnerable to CVE-2019-20372")
                    found_vulnerabilities.append('CVE-2019-20372')
            
            # Check for PHP vulnerabilities
            if 'php' in banner_lower:
                version_match = re.search(r'php/(\d+\.\d+\.\d+)', banner_lower)
                if version_match:
                    print_result("PHP Version", version_match.group(1))
            
            # Check for IIS vulnerabilities
            if 'microsoft-iis' in banner_lower or 'iis' in banner_lower:
                if '8.5' in banner:
                    print_danger("Potentially vulnerable to CVE-2021-26855")
                    found_vulnerabilities.append('CVE-2021-26855')
                if '10.0' in banner:
                    print_danger("Potentially vulnerable to CVE-2021-34527")
                    found_vulnerabilities.append('CVE-2021-34527')
            
            if found_vulnerabilities:
                self.vulnerabilities.extend(found_vulnerabilities)
            else:
                print_warning("No known CVEs matched in banner")
            
            self.results['cves'] = found_vulnerabilities
            return found_vulnerabilities
        except Exception as e:
            print_warning(f"CVE check failed: {str(e)}")
            return []
    
    def test_xss_vulnerability(self, url):
        """Test for basic XSS vulnerability"""
        try:
            print_section("XSS Vulnerability Testing")
            
            url_with_param = f"{url}/?q=test" if '?' not in url else url + "&q=test"
            
            xss_found = False
            for payload in self.TEST_PAYLOADS['xss']:
                try:
                    test_url = f"{url_with_param.replace('test', payload)}"
                    response = requests.get(test_url, timeout=5, verify=False)
                    
                    if payload in response.text:
                        print_danger(f"Potential XSS found with payload: {payload[:50]}")
                        xss_found = True
                        self.vulnerabilities.append('XSS')
                        break
                except:
                    pass
            
            if not xss_found:
                print_warning("No obvious XSS vulnerabilities detected in quick test")
            
            self.results['xss_tested'] = xss_found
            return xss_found
        except Exception as e:
            print_warning(f"XSS test failed: {str(e)}")
            return False
    
    def test_sqli_vulnerability(self, url):
        """Test for basic SQL injection"""
        try:
            print_section("SQL Injection Testing")
            
            # Check response differences
            try:
                normal_response = requests.get(url, timeout=5, verify=False)
                normal_len = len(normal_response.text)
                
                # Test with simple SQLi payload
                sqli_url = f"{url}?id=1' OR '1'='1"
                sqli_response = requests.get(sqli_url, timeout=5, verify=False)
                sqli_len = len(sqli_response.text)
                
                if abs(normal_len - sqli_len) > 50:  # Significant difference
                    print_warning("Response length differs significantly - possible SQLi")
                    self.vulnerabilities.append('SQLi')
                else:
                    print_warning("No obvious SQLi detected in quick test")
                
                self.results['sqli_tested'] = True
            except:
                pass
            
            return False
        except Exception as e:
            print_warning(f"SQLi test failed: {str(e)}")
            return False
    
    def test_lfi_vulnerability(self, url):
        """Test for basic LFI vulnerability"""
        try:
            print_section("Local File Inclusion Testing")
            
            lfi_found = False
            for payload in self.TEST_PAYLOADS['lfi'][:1]:  # Test one
                try:
                    test_url = f"{url}?file={payload}"
                    response = requests.get(test_url, timeout=5, verify=False)
                    
                    if 'root:' in response.text or 'Administrator' in response.text:
                        print_danger("Potential LFI found!")
                        lfi_found = True
                        self.vulnerabilities.append('LFI')
                        break
                except:
                    pass
            
            if not lfi_found:
                print_warning("No obvious LFI detected in quick test")
            
            self.results['lfi_tested'] = lfi_found
            return lfi_found
        except Exception as e:
            print_warning(f"LFI test failed: {str(e)}")
            return False
    
    def check_security_headers(self, headers):
        """Check for important security headers"""
        try:
            print_section("Security Headers Analysis")
            
            important_headers = {
                'Strict-Transport-Security': 'HSTS',
                'X-Content-Type-Options': 'X-Content-Type-Options',
                'X-Frame-Options': 'X-Frame-Options (Clickjacking)',
                'X-XSS-Protection': 'X-XSS-Protection',
                'Content-Security-Policy': 'CSP',
                'Referrer-Policy': 'Referrer-Policy',
            }
            
            found_headers = []
            missing_headers = []
            
            for header_name, description in important_headers.items():
                if header_name in headers:
                    print_success(f"✓ {description} is present")
                    found_headers.append(header_name)
                else:
                    print_warning(f"✗ {description} is MISSING")
                    missing_headers.append(header_name)
            
            self.results['security_headers_found'] = found_headers
            self.results['security_headers_missing'] = missing_headers
            
            return found_headers, missing_headers
        except Exception as e:
            print_warning(f"Security headers check failed: {str(e)}")
            return [], []
    
    def run_all(self, banner, url=None, headers=None):
        """Run all security checks"""
        self.check_banner_for_cves(banner)
        
        if headers:
            self.check_security_headers(headers)
        
        if url:
            # Note: These are basic tests and may cause requests to target
            # In production, these should be disabled or require explicit consent
            pass
        
        self.results['vulnerabilities_found'] = self.vulnerabilities
        return self.results
