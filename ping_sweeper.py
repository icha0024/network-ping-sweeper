#!/usr/bin/env python3
"""
Network Ping Sweeper
A simple tool to discover live hosts on a network range

Author: SomeRandomDev
License: MIT
"""

import subprocess
import sys
import time
import ipaddress
import threading
import argparse
import csv
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

class NetworkPingSweeper:
    def __init__(self, timeout=1, max_threads=50):
        self.timeout = timeout
        self.max_threads = max_threads
        self.live_hosts = []
        self.scanned_hosts = 0
        self.total_hosts = 0
        self.lock = threading.Lock()  # For thread-safe operations
        self.scan_start_time = None
        self.scan_end_time = None
        
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
            
            # Run ping command and capture result
            result = subprocess.run(
                cmd, 
                stdout=subprocess.DEVNULL,  # Hide output
                stderr=subprocess.DEVNULL,  # Hide errors
                timeout=self.timeout + 1    # Extra second for process overhead
            )
            
            # Thread-safe counter update
            with self.lock:
                self.scanned_hosts += 1
                progress = (self.scanned_hosts / self.total_hosts) * 100
            
            # Check if ping was successful (return code 0 = success)
            if result.returncode == 0:
                with self.lock:
                    self.live_hosts.append(str(ip))
                print(f"[{self.scanned_hosts:3d}/{self.total_hosts}] {ip:15} ✅ LIVE ({progress:5.1f}%)")
                return True
            else:
                print(f"[{self.scanned_hosts:3d}/{self.total_hosts}] {ip:15} ❌ DOWN ({progress:5.1f}%)")
                return False
                
        except subprocess.TimeoutExpired:
            with self.lock:
                self.scanned_hosts += 1
                progress = (self.scanned_hosts / self.total_hosts) * 100
            print(f"[{self.scanned_hosts:3d}/{self.total_hosts}] {ip:15} ⏱️  TIMEOUT ({progress:5.1f}%)")
            return False
        except Exception as e:
            with self.lock:
                self.scanned_hosts += 1
                progress = (self.scanned_hosts / self.total_hosts) * 100
            print(f"[{self.scanned_hosts:3d}/{self.total_hosts}] {ip:15} ❌ ERROR: {e} ({progress:5.1f}%)")
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
        Sweep a network range and find live hosts using multi-threading
        
        Args:
            network_range (str): Network range to scan
            
        Returns:
            list: List of live host IP addresses
        """
        try:
            # Parse the network range
            ip_list = self.parse_network_range(network_range)
            
            print(f"\n🔍 Starting ping sweep of {network_range}")
            print(f"📊 Scanning {len(ip_list)} hosts with {self.max_threads} threads")
            print(f"⏱️  Timeout: {self.timeout} seconds per host")
            print("-" * 70)
            
            # Initialize counters
            self.live_hosts = []
            self.scanned_hosts = 0
            self.total_hosts = len(ip_list)
            
            self.scan_start_time = time.time()
            
            # Use ThreadPoolExecutor for concurrent pings
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                # Submit all ping tasks
                futures = [executor.submit(self.ping_host, ip) for ip in ip_list]
                
                # Wait for all tasks to complete
                for future in futures:
                    try:
                        future.result()  # This will raise any exceptions that occurred
                    except Exception as e:
                        print(f"❌ Thread error: {e}")
            
            self.scan_end_time = time.time()
            
            # Results summary
            print(f"\n" + "=" * 70)
            print(f"🎯 SCAN COMPLETE")
            print(f"⏱️  Time taken: {self.scan_end_time - self.scan_start_time:.2f} seconds")
            print(f"📈 Hosts scanned: {self.scanned_hosts}/{self.total_hosts}")
            print(f"✅ Live hosts found: {len(self.live_hosts)}")
            print("=" * 70)
            
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
            self.scan_end_time = time.time()
            print(f"\n\n⚠️  Scan interrupted by user")
            print(f"📊 Progress: {self.scanned_hosts}/{self.total_hosts} hosts scanned")
            if self.live_hosts:
                print(f"✅ Live hosts found so far: {len(self.live_hosts)}")
                for host in sorted(self.live_hosts, key=ipaddress.ip_address):
                    print(f"   • {host}")
            return self.live_hosts

    def save_results(self, network_range, output_file, file_format='txt'):
        """
        Save scan results to a file
        
        Args:
            network_range (str): The network range that was scanned
            output_file (str): Output file path
            file_format (str): File format ('txt', 'csv', 'json')
        """
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            scan_time = self.scan_end_time - self.scan_start_time if self.scan_end_time and self.scan_start_time else 0
            
            if file_format.lower() == 'csv':
                with open(output_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Network Range', 'Scan Time', 'Timeout', 'Threads', 'Total Hosts', 'Live Hosts', 'Scan Duration'])
                    writer.writerow([network_range, timestamp, self.timeout, self.max_threads, self.total_hosts, len(self.live_hosts), f"{scan_time:.2f}s"])
                    writer.writerow([])  # Empty row
                    writer.writerow(['Live Host IPs'])
                    for host in sorted(self.live_hosts, key=ipaddress.ip_address):
                        writer.writerow([host])
                        
            elif file_format.lower() == 'json':
                data = {
                    'scan_info': {
                        'network_range': network_range,
                        'timestamp': timestamp,
                        'timeout': self.timeout,
                        'threads': self.max_threads,
                        'total_hosts': self.total_hosts,
                        'live_hosts_count': len(self.live_hosts),
                        'scan_duration_seconds': round(scan_time, 2)
                    },
                    'live_hosts': sorted(self.live_hosts, key=ipaddress.ip_address)
                }
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)
                    
            else:  # Default to txt format
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write("Network Ping Sweep Results\n")
                    f.write("=" * 50 + "\n")
                    f.write(f"Network Range: {network_range}\n")
                    f.write(f"Scan Time: {timestamp}\n")
                    f.write(f"Timeout: {self.timeout} seconds\n")
                    f.write(f"Threads: {self.max_threads}\n")
                    f.write(f"Total Hosts Scanned: {self.total_hosts}\n")
                    f.write(f"Live Hosts Found: {len(self.live_hosts)}\n")
                    f.write(f"Scan Duration: {scan_time:.2f} seconds\n")
                    f.write("-" * 30 + "\n\n")
                    
                    if self.live_hosts:
                        f.write("Live Host IPs:\n")
                        for host in sorted(self.live_hosts, key=ipaddress.ip_address):
                            f.write(f"  • {host}\n")
                    else:
                        f.write("No live hosts found.\n")
            
            print(f"💾 Results saved to {output_file}")
            return True
            
        except Exception as e:
            print(f"❌ Error saving results: {e}")
            return False

def get_network_range():
    """Get network range from user with validation and examples"""
    print("📋 NETWORK RANGE OPTIONS:")
    print("   1. Single IP:    192.168.1.1")
    print("   2. CIDR range:   192.168.1.0/24    (scans .1 to .254)")
    print("   3. IP range:     192.168.1.1-50    (scans .1 to .50)")
    print("   4. Full subnet:  192.168.0.0/24    (scans 192.168.0.1-254)")
    print()
    
    while True:
        network_range = input("🌐 Enter network range to scan: ").strip()
        
        if not network_range:
            print("❌ Please enter a network range")
            continue
        
        # Validate the input by trying to parse it
        sweeper = NetworkPingSweeper()
        try:
            ip_list = sweeper.parse_network_range(network_range)
            
            # Show what will be scanned
            if len(ip_list) == 1:
                print(f"✅ Will scan: {ip_list[0]}")
            elif len(ip_list) <= 5:
                print(f"✅ Will scan: {', '.join(ip_list)}")
            else:
                print(f"✅ Will scan: {ip_list[0]} through {ip_list[-1]} ({len(ip_list)} hosts)")
            
            # Warn for large scans
            if len(ip_list) > 100:
                print(f"⚠️  Warning: This will scan {len(ip_list)} hosts. This may take a while.")
                confirm = input("Continue? (y/n): ").strip().lower()
                if confirm not in ['y', 'yes']:
                    continue
            
            return network_range
            
        except ValueError as e:
            print(f"❌ Invalid network range: {e}")
            print("💡 Please try again with a valid format")
            continue

def get_timeout():
    """Get timeout setting from user with validation"""
    print("\n⏱️  TIMEOUT SETTINGS:")
    print("   • Fast scan:     1 second  (may miss slow devices)")
    print("   • Balanced:      2 seconds (recommended)")
    print("   • Thorough:      5 seconds (catches slow devices)")
    print()
    
    while True:
        timeout_input = input("Enter ping timeout in seconds [2]: ").strip()
        
        if not timeout_input:
            return 2  # Default
        
        try:
            timeout = int(timeout_input)
            if timeout < 1:
                print("❌ Timeout must be at least 1 second")
                continue
            elif timeout > 10:
                print("⚠️  Warning: Timeout over 10 seconds may be very slow")
                confirm = input("Continue with this timeout? (y/n): ").strip().lower()
                if confirm not in ['y', 'yes']:
                    continue
            
            return timeout
            
        except ValueError:
            print("❌ Please enter a valid number")
            continue

def get_thread_count():
    """Get thread count from user with validation"""
    print("\n🧵 THREAD SETTINGS:")
    print("   • Conservative:  25 threads  (safe for most systems)")
    print("   • Balanced:      50 threads  (recommended)")
    print("   • Aggressive:    100 threads (fast but may overwhelm network)")
    print()
    
    while True:
        threads_input = input("Enter number of threads [50]: ").strip()
        
        if not threads_input:
            return 50  # Default
        
        try:
            threads = int(threads_input)
            if threads < 1:
                print("❌ Thread count must be at least 1")
                continue
            elif threads > 200:
                print("❌ Maximum 200 threads allowed to prevent system overload")
                continue
            elif threads > 100:
                print("⚠️  Warning: High thread count may overwhelm your network or system")
                confirm = input("Continue with this many threads? (y/n): ").strip().lower()
                if confirm not in ['y', 'yes']:
                    continue
            
            return threads
            
        except ValueError:
            print("❌ Please enter a valid number")
            continue

def get_output_settings():
    """Get output file settings from user"""
    print("\n💾 SAVE RESULTS:")
    save_choice = input("Save results to file? (y/n) [n]: ").strip().lower()
    
    if save_choice not in ['y', 'yes']:
        return None, None
    
    # Get filename
    default_filename = f"ping_sweep_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    filename = input(f"Enter filename [{default_filename}]: ").strip()
    if not filename:
        filename = default_filename
    
    # Get format
    print("\nFile formats:")
    print("   1. txt  - Human-readable text (default)")
    print("   2. csv  - Comma-separated values")
    print("   3. json - JSON format")
    
    format_choice = input("Choose format (1/2/3) [1]: ").strip()
    format_map = {'1': 'txt', '2': 'csv', '3': 'json'}
    file_format = format_map.get(format_choice, 'txt')
    
    # Ensure correct extension
    base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename
    filename = f"{base_name}.{file_format}"
    
    return filename, file_format

def run_interactive_mode():
    """Run the tool in interactive mode"""
    print("🔍 Network Ping Sweeper v1.0.0")
    print("=" * 50)
    print("⚠️  IMPORTANT: Only use on networks you own or have explicit permission to scan!")
    print("   Unauthorized network scanning may be illegal in your jurisdiction.")
    print("=" * 50)
    
    try:
        # Get all settings from user
        network_range = get_network_range()
        timeout = get_timeout()
        threads = get_thread_count()
        output_file, file_format = get_output_settings()
        
        # Confirm settings before starting
        print(f"\n📋 SCAN CONFIGURATION:")
        print(f"   Network: {network_range}")
        print(f"   Timeout: {timeout} seconds")
        print(f"   Threads: {threads}")
        if output_file:
            print(f"   Output: {output_file} ({file_format})")
        print()
        
        input("Press Enter to start scanning... ")
        
        # Create sweeper and run scan
        sweeper = NetworkPingSweeper(timeout=timeout, max_threads=threads)
        live_hosts = sweeper.sweep_network(network_range)
        
        # Save results if requested
        if output_file and live_hosts:
            sweeper.save_results(network_range, output_file, file_format)
        
        print(f"\n🏁 Scan finished. Found {len(live_hosts)} live hosts.")
        
    except KeyboardInterrupt:
        print(f"\n\n👋 Scan cancelled by user. Goodbye!")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")

def main():
    """Main entry point with command line argument support"""
    parser = argparse.ArgumentParser(
        description="Network Ping Sweeper - Discover live hosts on a network",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Interactive mode
  %(prog)s 192.168.1.0/24               # Scan entire subnet
  %(prog)s 192.168.1.1-50               # Scan IP range
  %(prog)s 8.8.8.8                      # Scan single IP
  %(prog)s 192.168.1.0/24 -t 3 --threads 25 -o results.txt  # Custom settings with output
        """)
    
    parser.add_argument(
        'network', 
        nargs='?',  # Optional positional argument
        help='Network range to scan (e.g., 192.168.1.0/24, 192.168.1.1-50, 8.8.8.8)'
    )
    parser.add_argument(
        '-t', '--timeout', 
        type=int, 
        default=2, 
        metavar='SECONDS',
        help='Ping timeout in seconds'
    )
    parser.add_argument(
        '--threads', 
        type=int, 
        default=50, 
        metavar='COUNT',
        help='Number of concurrent threads'
    )
    parser.add_argument(
        '-o', '--output',
        metavar='FILE',
        help='Save results to file (format determined by extension: .txt, .csv, .json)'
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Quiet mode - only show live hosts'
    )
    parser.add_argument(
        '--version',
        action='version',
        version='Network Ping Sweeper v1.0.0'
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    # Validate arguments
    if args.timeout < 1:
        print("❌ Error: Timeout must be at least 1 second")
        sys.exit(1)
    elif args.timeout > 30:
        print("❌ Error: Timeout cannot exceed 30 seconds")
        sys.exit(1)
    
    if args.threads < 1:
        print("❌ Error: Thread count must be at least 1")
        sys.exit(1)
    elif args.threads > 200:
        print("❌ Error: Thread count cannot exceed 200")
        sys.exit(1)
    
    # Show warning (unless in quiet mode)
    if not args.quiet:
        print("⚠️  WARNING: Only use on networks you own or have explicit permission to scan!")
        print()
    
    # If no network provided, run interactive mode
    if not args.network:
        run_interactive_mode()
        return
    
    # Command-line mode
    try:
        sweeper = NetworkPingSweeper(timeout=args.timeout, max_threads=args.threads)
        live_hosts = sweeper.sweep_network(args.network)
        
        # Save results if output file specified
        if args.output and live_hosts:
            # Determine format from file extension
            file_format = 'txt'
            if args.output.lower().endswith('.csv'):
                file_format = 'csv'
            elif args.output.lower().endswith('.json'):
                file_format = 'json'
            
            sweeper.save_results(args.network, args.output, file_format)
        
        if args.quiet and live_hosts:
            # In quiet mode, just print the live hosts
            for host in sorted(live_hosts, key=ipaddress.ip_address):
                print(host)
        elif not args.quiet:
            print(f"\n🏁 Scan finished. Found {len(live_hosts)} live hosts.")
        
        # Exit code: 0 if hosts found, 1 if none found
        sys.exit(0 if live_hosts else 1)
        
    except KeyboardInterrupt:
        print(f"\n\n⚠️  Scan interrupted by user")
        sys.exit(130)  # Standard exit code for SIGINT
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()