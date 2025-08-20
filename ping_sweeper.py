#!/usr/bin/env python3
"""
Network Ping Sweeper
A simple tool to discover live hosts on a network range

Author: SomeRandomDev
Version: 0.2.0
License: MIT
"""

import subprocess
import sys
import time
import ipaddress

class NetworkPingSweeper:
    def __init__(self, timeout=1):
        self.timeout = timeout
        self.live_hosts = []
        
    def ping_host(self, ip):
        """
        Ping a single host and return True if it responds
        
        Args:
            ip (str): IP address to ping
            
        Returns:
            bool: True if host responds, False otherwise
        """
        try:
            # Use different ping commands based on operating system
            if sys.platform.startswith('win'):
                # Windows: ping -n 1 -w timeout_ms IP
                cmd = ['ping', '-n', '1', '-w', str(self.timeout * 1000), str(ip)]
            else:
                # Linux/macOS: ping -c 1 -W timeout_sec IP
                cmd = ['ping', '-c', '1', '-W', str(self.timeout), str(ip)]
            
            print(f"Pinging {ip}...", end=' ')
            
            # Run ping command and capture result
            result = subprocess.run(
                cmd, 
                stdout=subprocess.DEVNULL,  # Hide output
                stderr=subprocess.DEVNULL,  # Hide errors
                timeout=self.timeout + 1    # Extra second for process overhead
            )
            
            # Check if ping was successful (return code 0 = success)
            if result.returncode == 0:
                print("✅ LIVE")
                self.live_hosts.append(str(ip))
                return True
            else:
                print("❌ DOWN")
                return False
                
        except subprocess.TimeoutExpired:
            print("⏱️  TIMEOUT")
            return False
        except Exception as e:
            print(f"❌ ERROR: {e}")
            return False

    def parse_network_range(self, network_input):
        """
        Parse network range input and return list of IP addresses to scan
        
        Args:
            network_input (str): Network range (e.g., '192.168.1.0/24', '10.0.0.1-10')
            
        Returns:
            list: List of IP addresses to scan
            
        Raises:
            ValueError: If network range is invalid
        """
        try:
            # Check if it's a CIDR notation
            if '/' in network_input:
                network = ipaddress.ip_network(network_input, strict=False)
                
                # For single host networks (/32), return just that host
                if network.num_addresses == 1:
                    return [str(network.network_address)]
                
                # For larger networks, return all host addresses
                return [str(ip) for ip in network.hosts()]
            
            # Check if it's a range notation
            elif '-' in network_input:
                parts = network_input.split('-')
                if len(parts) != 2:
                    raise ValueError("Range format should be 'IP-LASTOCTET' (e.g., 192.168.1.1-50)")
                
                start_ip = parts[0].strip()
                end_num = int(parts[1].strip())
                
                # Validate start IP
                start_addr = ipaddress.ip_address(start_ip)
                
                # Extract the base network (first 3 octets for IPv4)
                ip_parts = str(start_addr).split('.')
                if len(ip_parts) != 4:
                    raise ValueError("Only IPv4 ranges are supported")
                
                base_network = '.'.join(ip_parts[:3])
                start_num = int(ip_parts[3])
                
                # Validate range
                if end_num < start_num or end_num > 254:
                    raise ValueError(f"Invalid range: end number must be between {start_num} and 254")
                
                # Generate IP list
                return [f"{base_network}.{i}" for i in range(start_num, end_num + 1)]
            
            else:
                # Single IP address
                ipaddress.ip_address(network_input)  # Validate IP
                return [network_input]
                
        except ipaddress.AddressValueError:
            raise ValueError(f"Invalid IP address: {network_input}")
        except ValueError:
            raise
        except Exception as e:
            raise ValueError(f"Error parsing network range: {e}")

    def sweep_network(self, network_range):
        """
        Sweep a network range and find live hosts
        
        Args:
            network_range (str): Network range to scan
            
        Returns:
            list: List of live host IP addresses
        """
        try:
            # Parse the network range
            ip_list = self.parse_network_range(network_range)
            
            print(f"\n🔍 Starting ping sweep of {network_range}")
            print(f"📊 Scanning {len(ip_list)} hosts")
            print(f"⏱️  Timeout: {self.timeout} seconds per host")
            print("-" * 50)
            
            self.live_hosts = []  # Reset live hosts list
            start_time = time.time()
            
            # Ping each host in the range (sequentially for now)
            for i, ip in enumerate(ip_list, 1):
                print(f"[{i}/{len(ip_list)}] ", end='')
                self.ping_host(ip)
            
            end_time = time.time()
            
            # Results summary
            print(f"\n" + "=" * 50)
            print(f"🎯 SCAN COMPLETE")
            print(f"⏱️  Time taken: {end_time - start_time:.2f} seconds")
            print(f"✅ Live hosts found: {len(self.live_hosts)}")
            print("=" * 50)
            
            if self.live_hosts:
                print(f"\n🌐 LIVE HOSTS:")
                for host in sorted(self.live_hosts, key=ipaddress.ip_address):
                    print(f"   • {host}")
            else:
                print(f"\n❌ No live hosts found in {network_range}")
                
            return self.live_hosts
            
        except ValueError as e:
            print(f"❌ Invalid network range: {e}")
            return []
        except KeyboardInterrupt:
            print(f"\n\n⚠️  Scan interrupted by user")
            if self.live_hosts:
                print(f"✅ Live hosts found so far: {len(self.live_hosts)}")
                for host in sorted(self.live_hosts, key=ipaddress.ip_address):
                    print(f"   • {host}")
            return self.live_hosts

def main():
    """Main entry point for the ping sweeper"""
    print("🔍 Network Ping Sweeper v0.3.0")
    print("⚠️  WARNING: Only use on networks you own or have permission to scan!")
    print()
    
    # Get network range from user
    print("Examples:")
    print("  Single IP: 192.168.1.1")
    print("  CIDR range: 192.168.1.0/24")
    print("  IP range: 192.168.1.1-50")
    print()
    
    network_range = input("Enter network range to scan: ").strip()
    
    if not network_range:
        print("❌ No network range provided")
        return
    
    # Get timeout setting
    try:
        timeout_input = input("Ping timeout in seconds [1]: ").strip()
        timeout = int(timeout_input) if timeout_input else 1
    except ValueError:
        timeout = 1
        print("⚠️  Invalid timeout, using default: 1 second")
    
    # Create sweeper and run scan
    sweeper = NetworkPingSweeper(timeout=timeout)
    live_hosts = sweeper.sweep_network(network_range)
    
    print(f"\n🏁 Scan finished. Found {len(live_hosts)} live hosts.")

if __name__ == "__main__":
    main()