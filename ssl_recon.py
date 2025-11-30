"""
SSL/TLS Certificate Analysis Module
"""
import socket
import ssl
from datetime import datetime
from utils import print_section, print_result, print_warning, print_success, print_danger


class SSLRecon:
    """SSL/TLS certificate analysis"""
    
    def __init__(self, target):
        self.target = target
        self.results = {}
    
    def get_certificate_info(self):
        """Get SSL certificate information"""
        try:
            print_section("SSL/TLS Certificate Analysis")
            
            # Remove protocol if present
            host = self.target.split('://')[1] if '://' in self.target else self.target
            host = host.split('/')[0]  # Remove path if present
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cert_bin = ssock.getpeercert(binary_form=True)
                    
                    if cert:
                        self.results['certificate'] = cert
                        
                        # Subject
                        subject = dict(x[0] for x in cert['subject'])
                        if 'commonName' in subject:
                            print_result("Common Name (CN)", subject['commonName'])
                        
                        # Organization
                        if 'organizationName' in subject:
                            print_result("Organization", subject['organizationName'])
                        
                        # Issuer
                        issuer = dict(x[0] for x in cert['issuer'])
                        if 'commonName' in issuer:
                            print_result("Issuer", issuer['commonName'])
                        
                        # Validity
                        not_before = cert['notBefore']
                        not_after = cert['notAfter']
                        print_result("Valid From", not_before)
                        print_result("Valid Until", not_after)
                        
                        # Check expiration
                        cert_datetime = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_until_expire = (cert_datetime - datetime.now()).days
                        
                        if days_until_expire < 0:
                            print_danger(f"Certificate EXPIRED {abs(days_until_expire)} days ago!")
                        elif days_until_expire < 30:
                            print_warning(f"Certificate expires in {days_until_expire} days")
                        else:
                            print_success(f"Certificate valid for {days_until_expire} more days")
                        
                        self.results['days_until_expiry'] = days_until_expire
                        
                        # SANs (Subject Alternative Names)
                        if 'subjectAltName' in cert:
                            sans = [x[1] for x in cert['subjectAltName']]
                            print_result("Alt Names", ", ".join(sans))
                            self.results['alt_names'] = sans
                        
                        # Version
                        print_result("Protocol Version", ssock.version())
                        self.results['ssl_version'] = ssock.version()
                        
                        # Cipher
                        cipher = ssock.cipher()
                        if cipher:
                            print_result("Cipher Suite", cipher[0])
                            self.results['cipher'] = cipher[0]
                        
                        return cert
                    else:
                        print_warning("No certificate data available")
                        return None
        except socket.timeout:
            print_warning("SSL connection timeout")
            return None
        except socket.gaierror:
            print_warning("DNS resolution failed")
            return None
        except ssl.SSLError as e:
            print_warning(f"SSL Error: {str(e)}")
            return None
        except Exception as e:
            print_warning(f"Certificate retrieval failed: {str(e)}")
            return None
    
    def run_all(self):
        """Run all SSL reconnaissance"""
        self.get_certificate_info()
        return self.results
