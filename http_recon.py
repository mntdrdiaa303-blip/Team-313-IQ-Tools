"""
HTTP Reconnaissance Module - Headers, server info, WAF/CDN detection, CMS detection
"""
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from utils import print_section, print_result, print_warning, print_success, print_danger


class HTTPRecon:
    """HTTP reconnaissance operations"""
    
    # CMS signatures
    CMS_SIGNATURES = {
        'wordpress': ['wp-content', 'wp-includes', 'wp-admin', 'WordPress'],
        'drupal': ['drupal', '/sites/all/', 'Drupal'],
        'joomla': ['joomla', '/components/', '/modules/', 'Joomla'],
        'magento': ['Magento', '/media/js/lib/', '/skin/'],
        'opencart': ['opencart', '/catalog/', '/admin/'],
        'prestashop': ['prestashop', '/modules/', 'PrestaShop'],
        'wix': ['wix', 'wixStores', 'wixvision'],
        'squarespace': ['squarespace', 'Squarespace'],
        'shopify': ['cdn.shopify.com', 'Shopify'],
    }
    
    # Common WAF/CDN signatures
    WAF_CDN_SIGNATURES = {
        'Cloudflare': ['cloudflare', 'cf-ray', 'cf-cache-status'],
        'AWS CloudFront': ['cloudfront', 'amazon', 'x-amz'],
        'Akamai': ['akamai', 'x-akamai-transformed'],
        'Imperva/Incapsula': ['imperva', 'incapsula', 'x-cdn'],
        'ModSecurity': ['modsecurity', 'x-mod-security'],
        'F5 BIG-IP': ['bigip', 'x-cnection'],
        'Barracuda': ['barracuda', 'x-barracuda'],
        'Fortinet': ['fortinet', 'fortiwebcloud'],
    }
    
    def __init__(self, target):
        self.target = target
        self.results = {}
        self.session = self._create_session()
    
    def _create_session(self):
        """Create a session with retries"""
        session = requests.Session()
        retry = Retry(connect=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session
    
    def get_headers(self):
        """Get HTTP headers"""
        try:
            print_section("HTTP Headers Analysis")
            url = f"http://{self.target}"
            
            response = self.session.head(url, timeout=10, allow_redirects=True)
            headers = response.headers
            self.results['headers'] = dict(headers)
            
            for key, value in headers.items():
                print_result(key, value[:80] + "..." if len(value) > 80 else value)
            
            return headers
        except Exception as e:
            print_warning(f"Header retrieval failed: {str(e)}")
            # Try with https
            try:
                url = f"https://{self.target}"
                response = self.session.head(url, timeout=10, allow_redirects=True, verify=False)
                headers = response.headers
                self.results['headers'] = dict(headers)
                for key, value in headers.items():
                    print_result(key, value[:80] + "..." if len(value) > 80 else value)
                return headers
            except Exception as e2:
                print_warning(f"HTTPS header retrieval also failed: {str(e2)}")
                return None
    
    def get_server_info(self):
        """Identify web server type"""
        try:
            print_section("Web Server Detection")
            headers = self.results.get('headers') or self.get_headers()
            
            if not headers:
                return None
            
            server = headers.get('Server', 'Unknown')
            self.results['server'] = server
            print_result("Server", server)
            
            # Try to extract version
            if 'nginx' in server.lower():
                print_success("Detected: Nginx")
            elif 'apache' in server.lower():
                print_success("Detected: Apache")
            elif 'iis' in server.lower():
                print_success("Detected: IIS (Microsoft)")
            elif 'microsoft-iis' in server.lower():
                print_success("Detected: Microsoft IIS")
            
            return server
        except Exception as e:
            print_warning(f"Server detection failed: {str(e)}")
            return None
    
    def detect_waf_cdn(self):
        """Detect WAF/CDN"""
        try:
            print_section("WAF/CDN Detection")
            headers = self.results.get('headers') or self.get_headers()
            
            if not headers:
                return None
            
            headers_str = str(headers).lower()
            detected_waf = []
            
            for waf_name, signatures in self.WAF_CDN_SIGNATURES.items():
                for sig in signatures:
                    if sig.lower() in headers_str:
                        detected_waf.append(waf_name)
                        print_success(f"Detected: {waf_name}")
                        break
            
            if not detected_waf:
                print_warning("No WAF/CDN detected")
            
            self.results['waf_cdn'] = detected_waf
            return detected_waf
        except Exception as e:
            print_warning(f"WAF/CDN detection failed: {str(e)}")
            return None
    
    def detect_cms(self):
        """Detect CMS used"""
        try:
            print_section("CMS Detection")
            url = f"http://{self.target}"
            
            try:
                response = self.session.get(url, timeout=10, allow_redirects=True)
            except:
                url = f"https://{self.target}"
                response = self.session.get(url, timeout=10, allow_redirects=True, verify=False)
            
            content = response.text.lower()
            headers = response.headers
            all_text = (str(headers) + content).lower()
            
            detected_cms = []
            
            for cms_name, signatures in self.CMS_SIGNATURES.items():
                for sig in signatures:
                    if sig.lower() in all_text:
                        detected_cms.append(cms_name)
                        print_success(f"Detected: {cms_name.upper()}")
                        break
            
            if not detected_cms:
                print_warning("No CMS detected")
            
            self.results['cms'] = detected_cms
            return detected_cms
        except Exception as e:
            print_warning(f"CMS detection failed: {str(e)}")
            return None
    
    def get_page_title(self):
        """Get page title"""
        try:
            print_section("Page Information")
            url = f"http://{self.target}"
            
            try:
                response = self.session.get(url, timeout=10, allow_redirects=True)
            except:
                url = f"https://{self.target}"
                response = self.session.get(url, timeout=10, allow_redirects=True, verify=False)
            
            soup = BeautifulSoup(response.text, 'html.parser')
            title = soup.find('title')
            
            if title:
                title_text = title.string
                print_result("Page Title", title_text)
                self.results['title'] = title_text
                return title_text
            else:
                print_warning("No page title found")
                return None
        except Exception as e:
            print_warning(f"Page title retrieval failed: {str(e)}")
            return None
    
    def check_common_files(self):
        """Check for common sensitive files"""
        try:
            print_section("Common Files/Directories Check")
            
            common_files = [
                'robots.txt',
                'sitemap.xml',
                '.htaccess',
                'web.config',
                'xmlrpc.php',
                'wp-admin',
                'admin',
                'administrator',
                '.env',
                'config.php',
                'database.yml'
            ]
            
            found_files = []
            url_base = f"http://{self.target}"
            
            for file in common_files:
                try:
                    response = self.session.head(f"{url_base}/{file}", timeout=5)
                    if response.status_code == 200:
                        found_files.append(file)
                        print_success(f"Found: /{file} (Status: {response.status_code})")
                except:
                    try:
                        url_base = f"https://{self.target}"
                        response = self.session.head(f"{url_base}/{file}", timeout=5, verify=False)
                        if response.status_code == 200:
                            found_files.append(file)
                            print_success(f"Found: /{file} (Status: {response.status_code})")
                    except:
                        pass
            
            if not found_files:
                print_warning("No common sensitive files found")
            
            self.results['common_files'] = found_files
            return found_files
        except Exception as e:
            print_warning(f"Common files check failed: {str(e)}")
            return None
    
    def run_all(self):
        """Run all HTTP reconnaissance"""
        self.get_headers()
        self.get_server_info()
        self.detect_waf_cdn()
        self.detect_cms()
        self.get_page_title()
        self.check_common_files()
        
        return self.results
