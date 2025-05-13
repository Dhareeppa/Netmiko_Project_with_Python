import nmap
import re
import os
import subprocess
from netmiko import ConnectHandler
from collections import Counter
from datetime import datetime
import argparse
import logging
import ipaddress


class NetworkAuditor:
    def __init__(self, network, log_file):
        try:
            self.network = ipaddress.ip_network(network, strict=False)  # Validate network range
        except ValueError as e:
            logging.error(f"Invalid network range: {e}")
            raise

        self.log_file = log_file
        self.devices = []
        self.config_dir = 'configurations'
        self.report_file = 'network_audit_report.txt'
        self.known_ips = set()
        self.username = os.getenv('DEVICE_USERNAME', 'admin')
        self.password = os.getenv('DEVICE_PASSWORD', 'password')

        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir)

        logging.basicConfig(filename='network_audit.log', level=logging.INFO,
                            format='%(asctime)s:%(levelname)s:%(message)s')

    @staticmethod
    def validate_ip(ip):
        try:
            ipaddress.ip_address(ip)  # Validate the IP address
            return True
        except ValueError:
            logging.warning(f"Invalid IP address found: {ip}")
            return False

    def discover_devices(self):
        logging.info("Starting device discovery.")
        nm = nmap.PortScanner()
        try:
            nm.scan(hosts=str(self.network), arguments='-sn')
            for host in nm.all_hosts():
                if 'mac' in nm[host]['addresses'] and self.validate_ip(host):
                    self.devices.append({
                        'ip': host,
                        'mac': nm[host]['addresses']['mac'],
                        'hostname': nm[host].hostname()
                    })
                    self.known_ips.add(host)
            logging.info(f"Discovered {len(self.devices)} devices.")
        except Exception as e:
            logging.error(f"Failed to discover devices: {str(e)}")

    def backup_configs(self):
        logging.info("Backing up device configurations.")
        for device in self.devices:
            try:
                connection = ConnectHandler(
                    device_type='cisco_ios',
                    ip=device['ip'],
                    username=self.username,
                    password=self.password
                )
                config = connection.send_command("show running-config")
                with open(f"{self.config_dir}/{device['ip']}_config.txt", "w") as f:
                    f.write(config)
                connection.disconnect()
                logging.info(f"Backed up configuration for {device['ip']}")
            except Exception as e:
                logging.error(f"Failed to backup {device['ip']}: {str(e)}")

    def analyze_security(self):
        logging.info("Analyzing security configurations.")
        security_issues = []
        for device in self.devices:
            config_file = f"{self.config_dir}/{device['ip']}_config.txt"
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = f.read()

                # Add more robust security checks
                if re.search(r'password \d{1,4}', config):
                    security_issues.append(f"CRITICAL: {device['ip']}: Weak password detected")

                if 'transport input telnet' in config:
                    security_issues.append(f"HIGH: {device['ip']}: Telnet is enabled (use SSH instead)")

                if not re.search(r'service password-encryption', config):
                    security_issues.append(f"MEDIUM: {device['ip']}: Password encryption not enabled")

                if not re.search(r'logging buffered', config):
                    security_issues.append(f"LOW: {device['ip']}: Logging not configured")

        return security_issues

    def analyze_traffic(self):
        logging.info("Analyzing network traffic.")
        traffic_data = []
        try:
            capture = subprocess.run(["sudo", "tcpdump", "-i", "any", "-c", "1000", "-nn"],
                                     capture_output=True, text=True, timeout=30)

            lines = capture.stdout.split('\n')
            for line in lines:
                if 'IP' in line:
                    parts = line.split()
                    src_ip = parts[2].split('.')[0]
                    dst_ip = parts[4].split('.')[0]
                    if self.validate_ip(src_ip) and self.validate_ip(dst_ip):
                        traffic_data.append((src_ip, dst_ip))

            traffic_summary = Counter(traffic_data)
            top_flows = traffic_summary.most_common(10)
            return top_flows

        except subprocess.TimeoutExpired:
            logging.error("Traffic capture timed out")
        except Exception as e:
            logging.error(f"Error during traffic analysis: {str(e)}")

        return []

    @property
    def analyze_logs(self):
        logging.info("Analyzing log files.")
        with open(self.log_file, 'r') as file:
            logs = file.readlines()

        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        timestamp_pattern = r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'

        ip_addresses, timestamps, critical_logs, high_level_logs, low_level_logs, unknown_ips = [[], [], [], [], [],
                                                                                                 set()]

        for log in logs:
            ip_match = re.search(ip_pattern, log)
            if ip_match:
                ip = ip_match.group()
                if self.validate_ip(ip):
                    ip_addresses.append(ip)
                    if ip not in self.known_ips:
                        unknown_ips.add(ip)

            timestamp_match = re.search(timestamp_pattern, log)
            if timestamp_match:
                timestamps.append(datetime.strptime(timestamp_match.group(), '%Y-%m-%d %H:%M:%S'))

            if 'CRITICAL' in log:
                critical_logs.append(log.strip())
            elif 'ERROR' in log or 'ALERT' in log:
                high_level_logs.append(log.strip())
            else:
                low_level_logs.append(log.strip())

        return ip_addresses, timestamps, critical_logs, high_level_logs, low_level_logs, unknown_ips

    def generate_report(self, security_issues, traffic_data, ip_addresses, timestamps, critical_logs, high_level_logs,
                        low_level_logs, unknown_ips):
        logging.info("Generating audit report.")
        report = "Network Audit Report\n" + "=" * 22 + "\n\n"

        report += "1. Discovered Devices\n" + "-" * 20 + "\n"
        for device in self.devices:
            report += f"IP: {device['ip']}, MAC: {device['mac']}, Hostname: {device['hostname']}\n"
        report += "\n"

        report += "2. Security Issues\n" + "-" * 16 + "\n"
        for issue in security_issues:
            report += f"- {issue}\n"
        report += "\n"

        report += "3. Network Traffic Analysis\n" + "-" * 26 + "\n"
        for src, dst in traffic_data:
            report += f"From {src} to {dst}: {traffic_data[(src, dst)]} packets\n"
        report += "\n"

        report += "4. Log Analysis\n" + "-" * 14 + "\n"
        report += "Top 5 IP Addresses:\n"
        for ip, count in Counter(ip_addresses).most_common(5):
            report += f"{ip}: {count} occurrences\n"
        report += "\n"

        if timestamps:
            report += f"Log Time Range: {min(timestamps)} to {max(timestamps)}\n\n"

        report += f"Critical Logs: {len(critical_logs)}\n"
        for log in critical_logs[:5]:
            report += f"- {log}\n"
        report += "\n"

        report += f"High-Level Logs: {len(high_level_logs)}\n"
        for log in high_level_logs[:5]:
            report += f"- {log}\n"
        report += "\n"

        report += f"Low-Level Logs: {len(low_level_logs)}\n"
        for log in low_level_logs[:5]:
            report += f"- {log}\n"
        report += "\n"

        report += "5. Unknown IP Alerts\n" + "-" * 19 + "\n"
        for ip in unknown_ips:
            report += f"ALERT: Unknown IP detected: {ip}\n"

        with open(self.report_file, 'w') as f:
            f.write(report)
        logging.info("Audit report generated successfully.")

    def run_audit(self):
        self.discover_devices()
        self.backup_configs()
        security_issues = self.analyze_security()
        traffic_data = self.analyze_traffic()
        ip_addresses, timestamps, critical_logs, high_level_logs, low_level_logs, unknown_ips = self.analyze_logs
        self.generate_report(security_issues, traffic_data, ip_addresses, timestamps, critical_logs, high_level_logs,
                             low_level_logs, unknown_ips)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Auditor Script")
    parser.add_argument("network", help="Network range to audit (e.g., 192.168.1.0/24)")
    parser.add_argument("log_file", help="Log file to analyze")
    args = parser.parse_args()

    auditor = NetworkAuditor(args.network, args.log_file)
    auditor.run_audit()
