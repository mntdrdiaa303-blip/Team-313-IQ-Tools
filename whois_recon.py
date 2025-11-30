"""
WHOIS Information Retrieval Module
"""
import whois
from datetime import datetime
from utils import print_section, print_result, print_warning, print_success, print_table


class WhoisRecon:
    """WHOIS information retrieval"""
    
    def __init__(self, target):
        self.target = target
        self.results = {}
    
    def get_whois_info(self):
        """Get WHOIS information"""
        try:
            print_section("WHOIS Information")
            
            whois_data = whois.whois(self.target)
            self.results['raw_whois'] = whois_data
            
            # Domain info
            if hasattr(whois_data, 'domain_name'):
                domain = whois_data.domain_name
                if isinstance(domain, list):
                    domain = domain[0]
                print_result("Domain Name", domain)
                self.results['domain_name'] = domain
            
            # Registrar
            if hasattr(whois_data, 'registrar'):
                print_result("Registrar", whois_data.registrar)
                self.results['registrar'] = whois_data.registrar
            
            # Creation date
            if hasattr(whois_data, 'creation_date'):
                creation_date = whois_data.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                print_result("Creation Date", str(creation_date))
                self.results['creation_date'] = creation_date
            
            # Expiration date
            if hasattr(whois_data, 'expiration_date'):
                expiration_date = whois_data.expiration_date
                if isinstance(expiration_date, list):
                    expiration_date = expiration_date[0]
                print_result("Expiration Date", str(expiration_date))
                
                # Calculate days until expiry
                try:
                    days_until_expire = (expiration_date - datetime.now()).days
                    if days_until_expire < 0:
                        print_warning(f"Domain EXPIRED {abs(days_until_expire)} days ago!")
                    elif days_until_expire < 30:
                        print_warning(f"Domain expires in {days_until_expire} days")
                    else:
                        print_success(f"Domain valid for {days_until_expire} more days")
                    self.results['days_until_expiry'] = days_until_expire
                except:
                    pass
            
            # Updated date
            if hasattr(whois_data, 'updated_date'):
                updated_date = whois_data.updated_date
                if isinstance(updated_date, list):
                    updated_date = updated_date[0]
                print_result("Last Updated", str(updated_date))
            
            # Status
            if hasattr(whois_data, 'status'):
                status = whois_data.status
                if isinstance(status, list):
                    status = status[0]
                print_result("Status", status)
                self.results['status'] = status
            
            # Registrant info
            if hasattr(whois_data, 'registrant_name'):
                print_result("Registrant Name", whois_data.registrant_name)
                self.results['registrant_name'] = whois_data.registrant_name
            
            # Name servers
            if hasattr(whois_data, 'name_servers'):
                nameservers = whois_data.name_servers
                if nameservers:
                    print_result("Name Servers", len(nameservers))
                    for ns in nameservers:
                        print_result("  ", ns)
                    self.results['name_servers'] = nameservers
            
            # Organization
            if hasattr(whois_data, 'org'):
                print_result("Organization", whois_data.org)
                self.results['organization'] = whois_data.org
            
            return whois_data
        except Exception as e:
            print_warning(f"WHOIS lookup failed: {str(e)}")
            return None
    
    def run_all(self):
        """Run WHOIS reconnaissance"""
        self.get_whois_info()
        return self.results
