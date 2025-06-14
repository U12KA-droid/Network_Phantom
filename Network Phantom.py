#!/usr/bin/env python3
"""
Advanced Professional Network Diagnostic Tool
==============================================

An enhanced stealthy network reconnaissance tool with advanced evasion techniques
including decoy IPs, custom TCP flags, MAC randomization, noise traffic injection,
and HTTP header spoofing for professional network diagnostics and security assessments.

Author: U12KA_droid
License: Educational/Professional Use Only
"""

import asyncio
import socket
import struct
import random
import time
import json
import logging
import ipaddress
import platform
import subprocess
import uuid
import os
import sys
from datetime import datetime
from typing import List, Dict, Tuple, Optional, Set, Union
from dataclasses import dataclass, asdict
import argparse
from contextlib import asynccontextmanager
import aiohttp
import secrets


@dataclass
class PortScanResult:
    """Data class for storing port scan results."""
    ip_address: str
    port: int
    status: str
    service: Optional[str]
    timestamp: str
    response_time: float
    scan_type: str
    decoy_used: bool = False


@dataclass
class NoiseTrafficConfig:
    """Configuration for noise traffic generation."""
    enabled: bool = False
    packets_per_batch: int = 5
    target_ports: List[int] = None
    protocols: List[str] = None


class StealthTechniques:
    """Advanced stealth techniques for network scanning."""
    
    @staticmethod
    def generate_fake_http_headers() -> Dict[str, str]:
        """Generate realistic HTTP headers to mimic browser traffic."""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0"
        ]
        
        accept_languages = [
            "en-US,en;q=0.9",
            "en-GB,en;q=0.9",
            "en-US,en;q=0.5",
            "fr-FR,fr;q=0.9,en;q=0.8",
            "de-DE,de;q=0.9,en;q=0.8"
        ]
        
        return {
            "User-Agent": random.choice(user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": random.choice(accept_languages),
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Cache-Control": "max-age=0"
        }
    
    @staticmethod
    async def change_mac_address(interface: str = None) -> bool:
        """
        Change MAC address of network interface (Linux/macOS).
        
        Args:
            interface: Network interface name (auto-detect if None)
            
        Returns:
            True if successful, False otherwise
        """
        if platform.system() not in ['Linux', 'Darwin']:
            return False
            
        try:
            # Auto-detect interface if not provided
            if not interface:
                if platform.system() == 'Linux':
                    result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        interface = result.stdout.split()[4]
                elif platform.system() == 'Darwin':
                    result = subprocess.run(['route', 'get', 'default'], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if 'interface:' in line:
                                interface = line.split(':')[1].strip()
                                break
            
            if not interface:
                return False
            
            # Generate random MAC address
            mac_bytes = [0x00, 0x16, 0x3e] + [random.randint(0x00, 0xff) for _ in range(3)]
            new_mac = ':'.join(f'{b:02x}' for b in mac_bytes)
            
            # Change MAC address
            if platform.system() == 'Linux':
                commands = [
                    ['sudo', 'ip', 'link', 'set', 'dev', interface, 'down'],
                    ['sudo', 'ip', 'link', 'set', 'dev', interface, 'address', new_mac],
                    ['sudo', 'ip', 'link', 'set', 'dev', interface, 'up']
                ]
            elif platform.system() == 'Darwin':
                commands = [
                    ['sudo', 'ifconfig', interface, 'ether', new_mac]
                ]
            
            for cmd in commands:
                result = subprocess.run(cmd, capture_output=True, timeout=10)
                if result.returncode != 0:
                    return False
            
            await asyncio.sleep(2)  # Allow interface to stabilize
            return True
            
        except Exception:
            return False
    
    @staticmethod
    def generate_decoy_ips(target_subnet: str, count: int = 5) -> List[str]:
        """
        Generate decoy IP addresses within the same subnet.
        
        Args:
            target_subnet: Target subnet in CIDR notation
            count: Number of decoy IPs to generate
            
        Returns:
            List of decoy IP addresses
        """
        try:
            network = ipaddress.ip_network(target_subnet, strict=False)
            all_ips = list(network.hosts())
            
            if len(all_ips) < count:
                count = len(all_ips)
            
            decoys = random.sample(all_ips, count)
            return [str(ip) for ip in decoys]
            
        except Exception:
            # Fallback to random private IPs
            return [f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}" 
                   for _ in range(count)]


class NoiseTrafficGenerator:
    """Generate noise traffic to obfuscate scanning activities."""
    
    def __init__(self, config: NoiseTrafficConfig):
        self.config = config
        self.noise_ports = config.target_ports or [53, 80, 443, 8080, 8443]
        self.protocols = config.protocols or ['TCP', 'UDP']
    
    async def generate_noise_packet(self, target_ip: str) -> None:
        """Generate a single noise packet."""
        try:
            protocol = random.choice(self.protocols)
            port = random.choice(self.noise_ports)
            
            if protocol == 'TCP':
                await self._send_tcp_noise(target_ip, port)
            elif protocol == 'UDP':
                await self._send_udp_noise(target_ip, port)
                
        except Exception:
            pass  # Silently ignore noise generation failures
    
    async def _send_tcp_noise(self, ip: str, port: int) -> None:
        """Send TCP noise packet."""
        try:
            future = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(future, timeout=1.0)
            
            # Send random data
            noise_data = secrets.token_bytes(random.randint(10, 100))
            writer.write(noise_data)
            await writer.drain()
            
            writer.close()
            await writer.wait_closed()
            
        except Exception:
            pass
    
    async def _send_udp_noise(self, ip: str, port: int) -> None:
        """Send UDP noise packet."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            
            noise_data = secrets.token_bytes(random.randint(10, 100))
            await asyncio.get_event_loop().sock_sendto(sock, noise_data, (ip, port))
            
            sock.close()
            
        except Exception:
            pass
    
    async def generate_noise_batch(self, target_ips: List[str]) -> None:
        """Generate a batch of noise packets."""
        if not self.config.enabled:
            return
            
        tasks = []
        for _ in range(self.config.packets_per_batch):
            target_ip = random.choice(target_ips)
            tasks.append(self.generate_noise_packet(target_ip))
        
        await asyncio.gather(*tasks, return_exceptions=True)


class AdvancedNetworkDiagnosticTool:
    """
    Advanced network diagnostic tool with sophisticated stealth capabilities.
    
    Features:
    - Decoy IP scanning
    - Custom TCP flag scanning (FIN, NULL, Xmas)
    - MAC address randomization
    - Noise traffic injection
    - HTTP header spoofing
    - Comprehensive evasion techniques
    """
    
    def __init__(self, 
                 subnet: str,
                 ports: List[int] = None,
                 max_concurrent: int = 50,
                 timeout: float = 3.0,
                 delay_range: Tuple[float, float] = (0.1, 2.0),
                 output_file: str = "advanced_network_scan_results",
                 stealth_mode: bool = True,
                 # Advanced stealth options
                 use_decoys: bool = False,
                 decoy_count: int = 5,
                 tcp_flags: List[str] = None,
                 change_mac: bool = False,
                 mac_change_interval: int = 100,
                 noise_traffic: bool = False,
                 fake_http_headers: bool = False):
        """
        Initialize the advanced network diagnostic tool.
        
        Args:
            subnet: Target subnet in CIDR notation
            ports: List of ports to scan
            max_concurrent: Maximum concurrent connections
            timeout: Connection timeout in seconds
            delay_range: Random delay range between scans
            output_file: Output file prefix
            stealth_mode: Enable basic stealth techniques
            use_decoys: Enable decoy IP scanning
            decoy_count: Number of decoy IPs to use
            tcp_flags: List of TCP flags to use ['SYN', 'FIN', 'NULL', 'XMAS']
            change_mac: Enable MAC address randomization
            mac_change_interval: Change MAC every N scans
            noise_traffic: Enable noise traffic generation
            fake_http_headers: Enable HTTP header spoofing
        """
        self.subnet = subnet
        self.ports = ports or self._get_common_ports()
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.delay_range = delay_range
        self.output_file = output_file
        self.stealth_mode = stealth_mode
        
        # Advanced stealth configuration
        self.use_decoys = use_decoys
        self.decoy_count = decoy_count
        self.tcp_flags = tcp_flags or ['SYN']
        self.change_mac = change_mac
        self.mac_change_interval = mac_change_interval
        self.fake_http_headers = fake_http_headers
        
        # Initialize components
        self.noise_generator = NoiseTrafficGenerator(
            NoiseTrafficConfig(enabled=noise_traffic)
        )
        self.stealth = StealthTechniques()
        
        # Results storage
        self.results: List[PortScanResult] = []
        self.discovered_hosts: Set[str] = set()
        self.scan_count = 0
        
        # Service detection and HTTP session
        self.service_map = self._build_service_map()
        self.http_session = None
        
        # Decoy IPs
        self.decoy_ips = []
        if self.use_decoys:
            self.decoy_ips = self.stealth.generate_decoy_ips(subnet, decoy_count)
        
        # Setup logging
        self._setup_logging()
    
    def _get_common_ports(self) -> List[int]:
        """Return list of commonly used ports for scanning."""
        return [
            21, 22, 23, 25, 42, 43, 53, 67, 69, 80, 88, 102, 110, 111, 135, 139,
            143, 389, 443, 445, 465, 514, 587, 631, 646, 990, 993, 995, 1080,
            1433, 1521, 1723, 1883, 2049, 2121, 2375, 3306, 3389, 5060, 5432,
            5672, 5900, 6379, 8080, 8443, 8888, 9200, 9418, 27017
        ]
    
    def _build_service_map(self) -> Dict[int, str]:
        """Build a mapping of common ports to services."""
        return {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
            993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB'
        }
    
    def _setup_logging(self):
        """Setup comprehensive logging configuration."""
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        
        # Create logs directory if it doesn't exist
        os.makedirs('logs', exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.FileHandler(f"logs/{self.output_file}_detailed.log"),
                logging.StreamHandler()
            ]
        )
        
        # Create separate logger for stealth operations
        self.logger = logging.getLogger('NetworkDiagnostic')
        self.stealth_logger = logging.getLogger('StealthOps')
        
        # Add stealth-specific handler
        stealth_handler = logging.FileHandler(f"logs/{self.output_file}_stealth.log")
        stealth_handler.setFormatter(logging.Formatter(log_format))
        self.stealth_logger.addHandler(stealth_handler)
        self.stealth_logger.setLevel(logging.DEBUG)
    
    def _generate_ip_list(self) -> List[str]:
        """Generate and shuffle list of IP addresses from subnet."""
        try:
            network = ipaddress.ip_network(self.subnet, strict=False)
            ip_list = [str(ip) for ip in network.hosts()]
            
            # Shuffle to avoid sequential scanning pattern
            random.shuffle(ip_list)
            
            self.logger.info(f"Generated {len(ip_list)} IPs from subnet {self.subnet}")
            if self.use_decoys:
                self.stealth_logger.info(f"Using {len(self.decoy_ips)} decoy IPs: {self.decoy_ips}")
            
            return ip_list
            
        except ValueError as e:
            self.logger.error(f"Invalid subnet format: {e}")
            return []
    
    async def _init_http_session(self):
        """Initialize HTTP session for web scanning."""
        if not self.http_session:
            connector = aiohttp.TCPConnector(
                limit=self.max_concurrent,
                ttl_dns_cache=300,
                use_dns_cache=True
            )
            
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self.http_session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                trust_env=False
            )
    
    async def _close_http_session(self):
        """Close HTTP session."""
        if self.http_session:
            await self.http_session.close()
            self.http_session = None
    
    async def _http_probe(self, ip: str, port: int) -> Optional[PortScanResult]:
        """
        Perform HTTP probe with fake headers.
        
        Args:
            ip: Target IP address
            port: Target port (80 or 443)
            
        Returns:
            PortScanResult if successful
        """
        if not self.fake_http_headers or port not in [80, 443]:
            return None
        
        await self._init_http_session()
        
        protocol = 'https' if port == 443 else 'http'
        url = f"{protocol}://{ip}:{port}/"
        
        start_time = time.time()
        
        try:
            headers = self.stealth.generate_fake_http_headers()
            
            async with self.http_session.get(url, headers=headers, ssl=False) as response:
                response_time = time.time() - start_time
                
                result = PortScanResult(
                    ip_address=ip,
                    port=port,
                    status='open',
                    service=f"HTTP/{response.status}",
                    timestamp=datetime.now().isoformat(),
                    response_time=round(response_time * 1000, 2),
                    scan_type='HTTP_PROBE'
                )
                
                self.stealth_logger.debug(f"HTTP probe successful: {ip}:{port} - Status: {response.status}")
                return result
                
        except Exception as e:
            self.stealth_logger.debug(f"HTTP probe failed for {ip}:{port}: {e}")
            return None
    
    async def _tcp_flag_scan(self, ip: str, port: int, flag_type: str) -> Optional[PortScanResult]:
        """
        Perform TCP scan with custom flags.
        
        Args:
            ip: Target IP address
            port: Target port
            flag_type: TCP flag type ('SYN', 'FIN', 'NULL', 'XMAS')
            
        Returns:
            PortScanResult if port responds
        """
        start_time = time.time()
        
        try:
            if flag_type == 'SYN':
                # Standard SYN scan
                future = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(future, timeout=self.timeout)
                writer.close()
                await writer.wait_closed()
                
                response_time = time.time() - start_time
                service = self._detect_service(port)
                
                result = PortScanResult(
                    ip_address=ip,
                    port=port,
                    status='open',
                    service=service,
                    timestamp=datetime.now().isoformat(),
                    response_time=round(response_time * 1000, 2),
                    scan_type=f'TCP_{flag_type}'
                )
                
                return result
            
            else:
                # Custom flag scans (FIN, NULL, XMAS) - simplified implementation
                # Note: Full implementation would require raw socket programming
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.setblocking(False)
                
                try:
                    await asyncio.get_event_loop().sock_connect(sock, (ip, port))
                    response_time = time.time() - start_time
                    
                    result = PortScanResult(
                        ip_address=ip,
                        port=port,
                        status='open',
                        service=self._detect_service(port),
                        timestamp=datetime.now().isoformat(),
                        response_time=round(response_time * 1000, 2),
                        scan_type=f'TCP_{flag_type}'
                    )
                    
                    return result
                    
                finally:
                    sock.close()
                    
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None
        except Exception as e:
            self.stealth_logger.debug(f"TCP {flag_type} scan error for {ip}:{port}: {e}")
            return None
    
    async def _decoy_scan(self, target_ip: str, port: int) -> Optional[PortScanResult]:
        """
        Perform scan using decoy IPs.
        
        Args:
            target_ip: Real target IP
            port: Target port
            
        Returns:
            PortScanResult from actual scan
        """
        if not self.use_decoys or not self.decoy_ips:
            return None
        
        # Launch decoy scans (fire and forget)
        decoy_tasks = []
        for decoy_ip in random.sample(self.decoy_ips, min(3, len(self.decoy_ips))):
            if decoy_ip != target_ip:
                task = asyncio.create_task(self._tcp_flag_scan(decoy_ip, port, 'SYN'))
                decoy_tasks.append(task)
        
        # Perform actual scan
        result = await self._tcp_flag_scan(target_ip, port, random.choice(self.tcp_flags))
        
        if result:
            result.decoy_used = True
            self.stealth_logger.debug(f"Decoy scan completed for {target_ip}:{port}")
        
        # Don't wait for decoy results, just let them complete
        for task in decoy_tasks:
            task.cancel()
        
        return result
    
    def _detect_service(self, port: int) -> str:
        """Lightweight service detection based on port number."""
        return self.service_map.get(port, 'Unknown')
    
    async def _stealth_delay(self):
        """Introduce randomized delay with jitter."""
        if self.stealth_mode:
            base_delay = random.uniform(*self.delay_range)
            jitter = random.uniform(0.1, 0.5)
            total_delay = base_delay + jitter
            await asyncio.sleep(total_delay)
    
    async def _maybe_change_mac(self):
        """Change MAC address if configured and interval reached."""
        if self.change_mac and self.scan_count % self.mac_change_interval == 0:
            self.stealth_logger.info("Attempting MAC address change...")
            success = await self.stealth.change_mac_address()
            if success:
                self.stealth_logger.info("MAC address changed successfully")
                await asyncio.sleep(5)  # Allow network to stabilize
            else:
                self.stealth_logger.warning("MAC address change failed")
    
    async def _scan_port_comprehensive(self, ip: str, port: int) -> List[PortScanResult]:
        """
        Perform comprehensive port scan using all configured techniques.
        
        Args:
            ip: Target IP address
            port: Target port
            
        Returns:
            List of scan results
        """
        results = []
        
        # Increment scan counter
        self.scan_count += 1
        
        # Maybe change MAC address
        await self._maybe_change_mac()
        
        # Apply stealth delay
        await self._stealth_delay()
        
        # Try decoy scan first
        if self.use_decoys:
            decoy_result = await self._decoy_scan(ip, port)
            if decoy_result:
                results.append(decoy_result)
        
        # Try HTTP probe for web ports
        if port in [80, 443] and self.fake_http_headers:
            http_result = await self._http_probe(ip, port)
            if http_result:
                results.append(http_result)
        
        # Try different TCP flag scans
        for flag_type in self.tcp_flags:
            if not (self.use_decoys and flag_type == 'SYN'):  # Avoid duplicate SYN if decoy used
                result = await self._tcp_flag_scan(ip, port, flag_type)
                if result:
                    results.append(result)
                    break  # Don't try other flags if one succeeds
        
        # Generate noise traffic
        if results:  # Only if we found something
            await self.noise_generator.generate_noise_batch([ip])
        
        return results
    
    async def _scan_host_ports(self, ip: str) -> List[PortScanResult]:
        """Scan all specified ports for a single host."""
        results = []
        
        # Shuffle ports to avoid pattern detection
        shuffled_ports = self.ports.copy()
        random.shuffle(shuffled_ports)
        
        for port in shuffled_ports:
            port_results = await self._scan_port_comprehensive(ip, port)
            results.extend(port_results)
            
            # Log discoveries
            for result in port_results:
                self.discovered_hosts.add(ip)
                self.logger.info(f"Open port found: {result.ip_address}:{result.port} "
                               f"({result.service}) - {result.response_time}ms [{result.scan_type}]")
        
        return results
    
    async def _scan_subnet(self) -> List[PortScanResult]:
        """Perform comprehensive subnet scan."""
        ip_list = self._generate_ip_list()
        if not ip_list:
            return []
        
        self.logger.info(f"Starting advanced subnet scan with {self.max_concurrent} concurrent connections")
        self.stealth_logger.info(f"Stealth configuration: Decoys={self.use_decoys}, "
                               f"Flags={self.tcp_flags}, MAC_Change={self.change_mac}, "
                               f"Noise={self.noise_generator.config.enabled}, "
                               f"HTTP_Headers={self.fake_http_headers}")
        
        # Create semaphore to limit concurrent connections
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def scan_with_limit(ip):
            async with semaphore:
                return await self._scan_host_ports(ip)
        
        # Execute scans with concurrency control
        tasks = [scan_with_limit(ip) for ip in ip_list]
        results_lists = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Flatten results and filter out exceptions
        all_results = []
        for result_list in results_lists:
            if isinstance(result_list, list):
                all_results.extend(result_list)
            else:
                self.logger.error(f"Scan error: {result_list}")
        
        return all_results
    
    def _get_system_info(self) -> Dict[str, str]:
        """Gather system information for scan metadata."""
        try:
            system_info = {
                'platform': platform.system(),
                'platform_version': platform.version(),
                'architecture': platform.machine(),
                'hostname': socket.gethostname(),
                'scan_id': str(uuid.uuid4())[:8],
                'stealth_features': {
                    'decoys_enabled': self.use_decoys,
                    'decoy_count': len(self.decoy_ips),
                    'tcp_flags': self.tcp_flags,
                    'mac_randomization': self.change_mac,
                    'noise_traffic': self.noise_generator.config.enabled,
                    'http_spoofing': self.fake_http_headers
                }
            }
            
            return system_info
            
        except Exception as e:
            self.logger.error(f"Error gathering system info: {e}")
            return {'scan_id': str(uuid.uuid4())[:8]}
    
    def _save_results(self):
        """Save comprehensive scan results."""
        if not self.results:
            self.logger.warning("No results to save")
            return
        
        # Prepare data for JSON export
        export_data = {
            'scan_metadata': {
                'subnet': self.subnet,
                'scan_time': datetime.now().isoformat(),
                'total_results': len(self.results),
                'unique_hosts': len(self.discovered_hosts),
                'scan_techniques_used': list(set(r.scan_type for r in self.results)),
                'system_info': self._get_system_info()
            },
            'discovered_hosts': list(self.discovered_hosts),
            'results': [asdict(result) for result in self.results],
            'stealth_summary': {
                'total_scans': self.scan_count,
                'decoy_scans': sum(1 for r in self.results if r.decoy_used),
                'scan_types': {scan_type: len([r for r in self.results if r.scan_type == scan_type]) 
                              for scan_type in set(r.scan_type for r in self.results)}
            }
        }
        
        # Save JSON file
        json_file = f"{self.output_file}.json"
        try:
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            self.logger.info(f"Results saved to {json_file}")
        except Exception as e:
            self.logger.error(f"Error saving JSON file: {e}")
        
        # Log summary
        self.logger.info(f"Advanced scan completed: {len(self.results)} open ports found "
                        f"on {len(self.discovered_hosts)} hosts using {self.scan_count} total scans")
    
    async def run_scan(self):
        """Execute the complete advanced network diagnostic scan."""
        self.logger.info("=== Advanced Network Diagnostic Tool Starting ===")
        self.logger.info(f"Target subnet: {self.subnet}")
        self.logger.info(f"Ports to scan: {len(self.ports)}")
        self.logger.info(f"Advanced stealth features enabled: "
                        f"Decoys={self.use_decoys}, TCP_Flags={self.tcp_flags}, "
                        f"MAC_Change={self.change_mac}, Noise={self.noise_generator.config.enabled}, "
                        f"HTTP_Headers={self.fake_http_headers}")
        
        start_time = time.time()
        
        try:
            # Initialize HTTP session if needed
            if self.fake_http_headers:
                await self._init_http_session()
            
            # Perform the scan
            self.results = await self._scan_subnet()
            
            # Save results
            self._save_results()
            
            # Print comprehensive summary
            elapsed_time = time.time() - start_time
            self.logger.info(f"Advanced scan completed in {elapsed_time:.2f} seconds")
            
            if self.results:
                print(f"\n=== ADVANCED SCAN SUMMARY ===")
                print(f"Hosts discovered: {len(self.discovered_hosts)}")
                print(f"Open ports found: {len(self.results)}")
                print(f"Total scans performed: {self.scan_count}")
                print(f"Scan duration: {elapsed_time:.2f}s")
                
                # Show scan techniques used
                scan_types = {}
                for result in self.results:
                    scan_types[result.scan_type] = scan_types.get(result.scan_type, 0) + 1
                
                print(f"\nScan techniques used:")
                for scan_type, count in sorted(scan_types.items(), key=lambda x: x[1], reverse=True):
                    print(f"  {scan_type}: {count} successful scans")
                
                # Show decoy usage
                decoy_count = sum(1 for r in self.results if r.decoy_used)
                if decoy_count > 0:
                    print(f"\nDecoy scans: {decoy_count}/{len(self.results)} ({decoy_count/len(self.results)*100:.1f}%)")
                
                # Show top discovered services
                services = {}
                for result in self.results:
                    service = result.service
                    services[service] = services.get(service, 0) + 1
                
                print(f"\nTop services discovered:")
                for service, count in sorted(services.items(), key=lambda x: x[1], reverse=True)[:5]:
                    print(f"  {service}: {count} instances")
                
                # Show stealth statistics
                print(f"\nStealth statistics:")
                if self.change_mac:
                    mac_changes = self.scan_count // self.mac_change_interval
                    print(f"  MAC address changes: {mac_changes}")
                if self.noise_generator.config.enabled:
                    print(f"  Noise traffic generated: ~{self.scan_count * self.noise_generator.config.packets_per_batch} packets")
                
            else:
                print("No open ports discovered in the scan.")
                
        except KeyboardInterrupt:
            self.logger.info("Scan interrupted by user")
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
        finally:
            # Cleanup
            await self._close_http_session()


def parse_arguments():
    """Parse command line arguments with advanced options."""
    parser = argparse.ArgumentParser(
        description='Advanced Professional Network Diagnostic Tool with Stealth Capabilities',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python network_diagnostic.py 192.168.1.0/24
  
  # Advanced stealth scan with all features
  python network_diagnostic.py 192.168.1.0/24 --use-decoys --decoy-count 8 --tcp-flags SYN,FIN,NULL --change-mac --noise-traffic --fake-http-headers
  
  # Custom port scan with specific techniques
  python network_diagnostic.py 10.0.0.0/24 --ports 80,443,22,3389 --tcp-flags XMAS --fake-http-headers --max-concurrent 100
  
  # High stealth scan
  python network_diagnostic.py 172.16.0.0/16 --use-decoys --change-mac --mac-interval 50 --noise-traffic --delay-min 2.0 --delay-max 8.0
        """
    )
    
    # Basic options
    parser.add_argument('subnet', help='Target subnet in CIDR notation (e.g., 192.168.1.0/24)')
    parser.add_argument('--ports', type=str, help='Comma-separated list of ports to scan')
    parser.add_argument('--max-concurrent', type=int, default=50, help='Maximum concurrent connections (default: 50)')
    parser.add_argument('--timeout', type=float, default=3.0, help='Connection timeout in seconds (default: 3.0)')
    parser.add_argument('--delay-min', type=float, default=0.1, help='Minimum delay between scans (default: 0.1)')
    parser.add_argument('--delay-max', type=float, default=2.0, help='Maximum delay between scans (default: 2.0)')
    parser.add_argument('--output', type=str, default='advanced_network_scan_results', help='Output file prefix')
    parser.add_argument('--no-stealth', action='store_true', help='Disable basic stealth mode')
    
    # Advanced stealth options
    stealth_group = parser.add_argument_group('Advanced Stealth Options')
    stealth_group.add_argument('--use-decoys', action='store_true', help='Enable decoy IP scanning')
    stealth_group.add_argument('--decoy-count', type=int, default=5, help='Number of decoy IPs to use (default: 5)')
    stealth_group.add_argument('--tcp-flags', type=str, default='SYN', help='TCP flags to use: SYN,FIN,NULL,XMAS (default: SYN)')
    stealth_group.add_argument('--change-mac', action='store_true', help='Enable MAC address randomization (requires sudo)')
    stealth_group.add_argument('--mac-interval', type=int, default=100, help='Change MAC every N scans (default: 100)')
    stealth_group.add_argument('--noise-traffic', action='store_true', help='Enable noise traffic generation')
    stealth_group.add_argument('--fake-http-headers', action='store_true', help='Enable HTTP header spoofing for web ports')
    
    return parser.parse_args()


def validate_arguments(args):
    """Validate and process command line arguments."""
    errors = []
    
    # Validate subnet
    try:
        ipaddress.ip_network(args.subnet, strict=False)
    except ValueError:
        errors.append(f"Invalid subnet format: {args.subnet}")
    
    # Validate ports
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(',')]
            for port in ports:
                if not (1 <= port <= 65535):
                    errors.append(f"Invalid port number: {port}")
            args.ports = ports
        except ValueError:
            errors.append("Invalid port format. Use comma-separated integers.")
    
    # Validate TCP flags
    valid_flags = {'SYN', 'FIN', 'NULL', 'XMAS'}
    if args.tcp_flags:
        flags = [flag.strip().upper() for flag in args.tcp_flags.split(',')]
        invalid_flags = set(flags) - valid_flags
        if invalid_flags:
            errors.append(f"Invalid TCP flags: {invalid_flags}. Valid flags: {valid_flags}")
        args.tcp_flags = flags
    
    # Validate numeric ranges
    if args.delay_min < 0 or args.delay_max < 0 or args.delay_min > args.delay_max:
        errors.append("Invalid delay range. Min and max must be positive and min <= max")
    
    if args.max_concurrent < 1:
        errors.append("Max concurrent connections must be at least 1")
    
    if args.timeout <= 0:
        errors.append("Timeout must be positive")
    
    if args.decoy_count < 1:
        errors.append("Decoy count must be at least 1")
    
    if args.mac_interval < 1:
        errors.append("MAC interval must be at least 1")
    
    # Check for sudo requirements
    if args.change_mac and os.geteuid() != 0 and platform.system() in ['Linux', 'Darwin']:
        errors.append("MAC address changing requires root privileges (run with sudo)")
    
    return errors


async def main():
    """Main execution function."""
    args = parse_arguments()
    
    # Validate arguments
    validation_errors = validate_arguments(args)
    if validation_errors:
        print("Validation errors:")
        for error in validation_errors:
            print(f"  - {error}")
        sys.exit(1)
    
    # Show warning for advanced features
    if any([args.use_decoys, args.change_mac, args.noise_traffic]):
        print("⚠️  WARNING: Advanced stealth features enabled. Use only on authorized networks.")
        print("   This tool is for legitimate security testing and network diagnostics only.")
        
        try:
            confirm = input("Continue? (y/N): ").lower().strip()
            if confirm != 'y':
                print("Scan cancelled.")
                sys.exit(0)
        except KeyboardInterrupt:
            print("\nScan cancelled.")
            sys.exit(0)
    
    # Initialize and run the advanced diagnostic tool
    tool = AdvancedNetworkDiagnosticTool(
        subnet=args.subnet,
        ports=args.ports,
        max_concurrent=args.max_concurrent,
        timeout=args.timeout,
        delay_range=(args.delay_min, args.delay_max),
        output_file=args.output,
        stealth_mode=not args.no_stealth,
        # Advanced stealth options
        use_decoys=args.use_decoys,
        decoy_count=args.decoy_count,
        tcp_flags=args.tcp_flags,
        change_mac=args.change_mac,
        mac_change_interval=args.mac_interval,
        noise_traffic=args.noise_traffic,
        fake_http_headers=args.fake_http_headers
    )
    
    await tool.run_scan()


if __name__ == "__main__":
    # Check Python version
    if sys.version_info < (3, 7):
        print("This tool requires Python 3.7 or higher.")
        sys.exit(1)
    
    # Check required modules
    try:
        import aiohttp
    except ImportError:
        print("Missing required module: aiohttp")
        print("Install with: pip install aiohttp")
        sys.exit(1)
    
    # Set up proper event loop handling for Windows
    if platform.system() == 'Windows':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    # Run the main function
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⚠️  Scan interrupted by user")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)