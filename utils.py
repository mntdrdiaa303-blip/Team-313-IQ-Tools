"""
Utility functions for DeepRecon - Formatting, colors, and common helpers
"""
from colorama import init, Fore, Style
import re

init(autoreset=True)


class Colors:
    """Color constants for CLI output"""
    HEADER = Fore.CYAN
    SUCCESS = Fore.GREEN
    WARNING = Fore.YELLOW
    DANGER = Fore.RED
    INFO = Fore.BLUE
    SECONDARY = Fore.MAGENTA
    RESET = Style.RESET_ALL


def print_banner():
    """Display Team 313 IQ banner"""
    banner = f"""{Colors.HEADER}
    ╔═══════════════════════════════════════════════════════╗
    ║                 🔍 DeepRecon 🔍                       ║
    ║              Team 313 IQ OSINT Tool                   ║
    ║  Advanced Reconnaissance & Security Assessment        ║
    ║           Educational Use Only - Use Responsibly      ║
    ╚═══════════════════════════════════════════════════════╝
{Colors.RESET}
    """
    print(banner)


def print_header(text):
    """Print a formatted section header"""
    print(f"\n{Colors.HEADER}{'='*60}")
    print(f"📋 {text.upper()}")
    print(f"{'='*60}{Colors.RESET}\n")


def print_section(title):
    """Print a subsection title"""
    print(f"{Colors.SECONDARY}>>> {title}{Colors.RESET}")


def print_success(message):
    """Print success message"""
    print(f"{Colors.SUCCESS}[✓] {message}{Colors.RESET}")


def print_info(message):
    """Print info message"""
    print(f"{Colors.INFO}[*] {message}{Colors.RESET}")


def print_warning(message):
    """Print warning message"""
    print(f"{Colors.WARNING}[!] {message}{Colors.RESET}")


def print_danger(message):
    """Print danger/alert message"""
    print(f"{Colors.DANGER}[✗] {message}{Colors.RESET}")


def print_result(key, value, level="info"):
    """Print key-value result"""
    if level == "success":
        color = Colors.SUCCESS
    elif level == "warning":
        color = Colors.WARNING
    elif level == "danger":
        color = Colors.DANGER
    else:
        color = Colors.INFO
    
    print(f"    {color}{key}: {value}{Colors.RESET}")


def print_table(headers, rows):
    """Print a formatted table"""
    if not rows:
        print_info("No data available")
        return
    
    # Calculate column widths
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))
    
    # Print header
    header_str = " | ".join(h.ljust(w) for h, w in zip(headers, col_widths))
    print(f"{Colors.HEADER}{header_str}{Colors.RESET}")
    print("-" * len(header_str))
    
    # Print rows
    for row in rows:
        row_str = " | ".join(str(cell).ljust(w) for cell, w in zip(row, col_widths))
        print(row_str)


def is_valid_domain(domain):
    """Validate domain format"""
    domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return re.match(domain_pattern, domain) is not None


def is_valid_ip(ip):
    """Validate IPv4 address format"""
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(ip_pattern, ip):
        return False
    
    parts = ip.split('.')
    return all(0 <= int(part) <= 255 for part in parts)


def is_ip_or_domain(target):
    """Check if target is IP or domain"""
    if is_valid_ip(target):
        return 'ip'
    elif is_valid_domain(target):
        return 'domain'
    return None


def format_dict_output(data, indent=2):
    """Format dictionary for pretty printing"""
    result = []
    for key, value in data.items():
        if isinstance(value, list):
            result.append(f"{' ' * indent}{key}:")
            for item in value:
                result.append(f"{' ' * (indent + 2)}- {item}")
        elif isinstance(value, dict):
            result.append(f"{' ' * indent}{key}:")
            for k, v in value.items():
                result.append(f"{' ' * (indent + 2)}{k}: {v}")
        else:
            result.append(f"{' ' * indent}{key}: {value}")
    return '\n'.join(result)


def truncate_text(text, length=50):
    """Truncate text to specified length"""
    if len(text) > length:
        return text[:length-3] + "..."
    return text
