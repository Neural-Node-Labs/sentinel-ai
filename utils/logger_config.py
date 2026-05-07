import logging
from pathlib import Path
import re
import os
from dotenv import load_dotenv
import socket  # Added for dynamic machine name detection
load_dotenv()

# --- Configuration ---
LOG_DIR = Path("logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "react_engine_secure.log"
# Dynamically get system identity
hostname = socket.gethostname()
# This often gets 'WORKGROUP' or the local domain name
domain = os.environ.get('USERDOMAIN', 'WORKGROUP')

class SecureFormatter(logging.Formatter):
    """Redact sensitive data from logs using pre-compiled regex."""

    # Pre-compiling for performance
    PATTERNS = [
        (re.compile(r'(api[_-]?key["\s:=]+)[\w-]+', re.I), r'\1***REDACTED***'),
        (re.compile(r'(Bearer\s+)[\w-]+', re.I), r'\1***REDACTED***'),
        (re.compile(r'(sk_[\w-]+)', re.I), r'***REDACTED***'),
        (re.compile(r'(password["\s:=]+)[^\s,}]+', re.I), r'\1***REDACTED***'),
        (re.compile(r'S-\d-\d-\d{2}-\d+-\d+-\d+-\d+', re.I), '***SID_REDACTED***'),
        # New: Redacts Account Names following specific Windows log labels
        (re.compile(r'(Account Name:\t\t)\S+', re.I), r'\1***USER_REDACTED***'),
        # DYNAMIC REDACTION:
        # Redacts the specific hostname detected at runtime
        (re.compile(re.escape(hostname), re.I), '***LOCAL_MACHINE_REDACTED***'),

        # Redacts the specific domain detected at runtime
        (re.compile(re.escape(domain), re.I), '***DOMAIN_REDACTED***'),

        # Catch-all for the "Account Domain" log line specifically
        (re.compile(r'(Account Domain:\t\t)\S+', re.I), r'\1***DOMAIN_REDACTED***'),
    ]


    def format(self, record):
        msg = super().format(record)
        for pattern, replacement in self.PATTERNS:
            msg = pattern.sub(replacement, msg)
        return msg


def setup_logging(level=logging.INFO):
    """Main entry point for log configuration."""

    log_format = '%(asctime)s [%(levelname)s] [%(name)s] %(message)s'
    formatter = SecureFormatter(log_format)

    # File Handler
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(formatter)

    # Stream (Console) Handler
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    # Root logger configuration
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Clear existing handlers to avoid duplicate logs
    if root_logger.hasHandlers():
        root_logger.handlers.clear()

    root_logger.addHandler(file_handler)
    root_logger.addHandler(stream_handler)


# Initialize once at the start of your app
setup_logging()
logger = logging.getLogger(__name__)