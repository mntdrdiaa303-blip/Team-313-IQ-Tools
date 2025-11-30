"""
DNS Reconnaissance Module - Analyze DNS records
"""
import dns.resolver
import dns.reversename
from utils import print_section, print_result, print_warning, print_table


class DNSRecon:
    """DNS reconnaissance operations"""
    
    def __init__(self, target):
        self.target = target
        self.results = {}
    
    def get_a_records(self):
        """Get A records"""
        try:
            print_section("A Records (IPv4)")
            answers = dns.resolver.resolve(self.target, 'A')
            records = [str(rdata) for rdata in answers]
            self.results['A'] = records
            for record in records:
                print_result("IPv4", record)
            return records
        except Exception as e:
            print_warning(f"A record lookup failed: {str(e)}")
            return None
    
    def get_aaaa_records(self):
        """Get AAAA records (IPv6)"""
        try:
            print_section("AAAA Records (IPv6)")
            answers = dns.resolver.resolve(self.target, 'AAAA')
            records = [str(rdata) for rdata in answers]
            self.results['AAAA'] = records
            for record in records:
                print_result("IPv6", record)
            return records
        except Exception as e:
            print_warning(f"AAAA record lookup failed: {str(e)}")
            return None
    
    def get_mx_records(self):
        """Get MX records"""
        try:
            print_section("MX Records (Mail Servers)")
            answers = dns.resolver.resolve(self.target, 'MX')
            records = []
            for rdata in answers:
                exchange = str(rdata.exchange).rstrip('.')
                preference = rdata.preference
                records.append((exchange, preference))
                print_result(f"Priority {preference}", exchange)
            self.results['MX'] = records
            return records
        except Exception as e:
            print_warning(f"MX record lookup failed: {str(e)}")
            return None
    
    def get_txt_records(self):
        """Get TXT records"""
        try:
            print_section("TXT Records")
            answers = dns.resolver.resolve(self.target, 'TXT')
            records = [str(rdata) for rdata in answers]
            self.results['TXT'] = records
            for record in records:
                print_result("TXT", record[:100] + "..." if len(record) > 100 else record)
            return records
        except Exception as e:
            print_warning(f"TXT record lookup failed: {str(e)}")
            return None
    
    def get_ns_records(self):
        """Get NS records"""
        try:
            print_section("NS Records (Nameservers)")
            answers = dns.resolver.resolve(self.target, 'NS')
            records = [str(rdata).rstrip('.') for rdata in answers]
            self.results['NS'] = records
            for record in records:
                print_result("Nameserver", record)
            return records
        except Exception as e:
            print_warning(f"NS record lookup failed: {str(e)}")
            return None
    
    def get_cname_records(self):
        """Get CNAME records"""
        try:
            print_section("CNAME Records")
            answers = dns.resolver.resolve(self.target, 'CNAME')
            records = [str(rdata).rstrip('.') for rdata in answers]
            self.results['CNAME'] = records
            for record in records:
                print_result("CNAME", record)
            return records
        except Exception as e:
            print_warning(f"CNAME record lookup failed: {str(e)}")
            return None
    
    def get_soa_records(self):
        """Get SOA records"""
        try:
            print_section("SOA Records (Start of Authority)")
            answers = dns.resolver.resolve(self.target, 'SOA')
            for rdata in answers:
                print_result("Primary Nameserver", str(rdata.mname).rstrip('.'))
                print_result("Responsible Email", str(rdata.rname).rstrip('.'))
                print_result("Serial", rdata.serial)
                print_result("Refresh", rdata.refresh)
                print_result("Retry", rdata.retry)
                print_result("Expire", rdata.expire)
                print_result("Minimum TTL", rdata.minimum)
            return answers
        except Exception as e:
            print_warning(f"SOA record lookup failed: {str(e)}")
            return None
    
    def run_all(self):
        """Run all DNS reconnaissance"""
        self.get_a_records()
        self.get_aaaa_records()
        self.get_mx_records()
        self.get_txt_records()
        self.get_ns_records()
        self.get_cname_records()
        self.get_soa_records()
        
        return self.results
