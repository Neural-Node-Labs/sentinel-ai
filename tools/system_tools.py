# ============================================================================
# FILE: tools/system_tools.py
# ============================================================================

import platform
import subprocess
import shlex
import re
from typing import Literal
from pathlib import Path
import os
from utils.logger_config import setup_logging
import logging
from dotenv import load_dotenv
load_dotenv()

# 1. Initialize the global configuration
setup_logging()
# 2. Get a logger for this specific file
logger = logging.getLogger(__name__)
SystemType = Literal["linux", "windows", "unknown"]


class SystemTools:
    """OS-Aware system tools for firewall management and log retrieval"""

    def __init__(self):
        self.os_type = self._detect_os()
        self.admin_ip = os.getenv("ADMIN_IP", "127.0.0.1")

    @staticmethod
    def _detect_os() -> SystemType:
        # testing only return "linux"
        """Detect operating system"""
        system = platform.system().lower()
        if "linux" in system:
            return "linux"
        elif "windows" in system:
            return "windows"
        return "unknown"

    def block_ip(self, ip_address: str, duration: str = "24h") -> dict[str, str]:
        """
        Block an IP address using system firewall.

        Args:
            ip_address: IP to block
            duration: Block duration (Linux only)

        Returns:
            Action result
        """
        # Safety: Never block admin IP
        if ip_address == self.admin_ip:
            return {
                "status": "denied",
                "reason": "Cannot block ADMIN_IP",
                "ip": ip_address
            }

        # Validate IP format
        if not self._validate_ip(ip_address):
            return {
                "status": "error",
                "reason": "Invalid IP address format",
                "ip": ip_address
            }

        try:
            if self.os_type == "linux":
                return self._block_ip_linux(ip_address, duration)
            elif self.os_type == "windows":
                return self._block_ip_windows(ip_address)
            else:
                return {
                    "status": "error",
                    "reason": f"Unsupported OS: {self.os_type}",
                    "ip": ip_address
                }
        except Exception as e:
            return {
                "status": "error",
                "reason": str(e),
                "ip": ip_address
            }

    def _block_ip_linux(self, ip: str, duration: str) -> dict[str, str]:
        """Block IP on Linux using iptables"""
        # Use shlex.quote for safety
        safe_ip = shlex.quote(ip)

        # Check if already blocked
        check_cmd = f"sudo iptables -L INPUT -n | grep {safe_ip}"
        result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)

        if result.returncode == 0:
            return {
                "status": "skipped",
                "reason": "IP already blocked",
                "ip": ip
            }

        # Block the IP
        block_cmd = f"sudo iptables -I INPUT -s {safe_ip} -j DROP"
        result = subprocess.run(block_cmd, shell=True, capture_output=True, text=True)

        if result.returncode == 0:
            return {
                "status": "success",
                "action": "blocked",
                "ip": ip,
                "duration": duration,
                "method": "iptables"
            }
        else:
            return {
                "status": "error",
                "reason": result.stderr,
                "ip": ip
            }

    def _block_ip_windows(self, ip: str) -> dict[str, str]:
        """Block IP on Windows using netsh"""
        # Validate with regex (already done, but double-check)
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
            return {"status": "error", "reason": "Invalid IP", "ip": ip}

        rule_name = f"Sentinel_Block_{ip.replace('.', '_')}"

        # Check if rule exists
        check_cmd = f'netsh advfirewall firewall show rule name="{rule_name}"'
        result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)

        if "No rules match" not in result.stdout:
            return {
                "status": "skipped",
                "reason": "IP already blocked",
                "ip": ip
            }

        # Create block rule
        block_cmd = (
            f'netsh advfirewall firewall add rule name="{rule_name}" '
            f'dir=in action=block remoteip={ip}'
        )
        result = subprocess.run(block_cmd, shell=True, capture_output=True, text=True)

        if result.returncode == 0:
            return {
                "status": "success",
                "action": "blocked",
                "ip": ip,
                "method": "netsh",
                "rule_name": rule_name
            }
        else:
            return {
                "status": "error",
                "reason": result.stderr,
                "ip": ip
            }

    def get_recent_logs(self, num_lines: int = 100) -> str:
        """
        Retrieve recent authentication logs.

        Args:
            num_lines: Number of log lines to retrieve

        Returns:
            Log content as string
        """
        log_path = os.getenv("LOG_PATH", "/var/log/auth.log")
        logger.info(f"get_recent_logs.log_path: {log_path}")

        try:
            if self.os_type == "linux":
                return self._get_logs_linux(log_path, num_lines)
            elif self.os_type == "windows":
                return self._get_logs_windows(num_lines)
            else:
                return f"Unsupported OS: {self.os_type}"
        except Exception as e:
            return f"Error retrieving logs: {e}"

    @staticmethod
    def _get_logs_linux(log_path: str, num_lines: int) -> str:
        """Get logs from Linux system"""
        if not Path(log_path).exists():
            return f"Log file not found: {log_path}"

        cmd = f"sudo tail -n {num_lines} {shlex.quote(log_path)}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        return result.stdout if result.returncode == 0 else result.stderr

    @staticmethod
    def _get_logs_windows(num_lines: int) -> str:
        """Get security logs from Windows Event Viewer"""
        cmd = (
            f'powershell "Get-WinEvent -LogName Security -MaxEvents {num_lines} '
            f'| Select-Object TimeCreated, Id, Message | Format-List"'
        )
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        return result.stdout if result.returncode == 0 else result.stderr

    @staticmethod
    def _validate_ip(ip: str) -> bool:
        """Validate IP address format"""
        pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        if not re.match(pattern, ip):
            return False

        # Check each octet is 0-255
        octets = ip.split(".")
        return all(0 <= int(octet) <= 255 for octet in octets)

