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

class NetworkPingSweeper:
    def __init__(self, timeout=1):
        self.timeout = timeout
        
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

def main():
    """Main entry point for the ping sweeper"""
    print("🔍 Network Ping Sweeper v0.2.0")
    print("⚠️  WARNING: Only use on networks you own or have permission to scan!")
    print()
    
    # Get IP from user for single ping demo
    ip = input("Enter an IP address to ping (e.g., 8.8.8.8): ").strip()
    
    if not ip:
        print("❌ No IP address provided")
        return
    
    sweeper = NetworkPingSweeper(timeout=2)
    print(f"\nPinging {ip}...")
    
    start_time = time.time()
    is_alive = sweeper.ping_host(ip)
    end_time = time.time()
    
    response_time = round((end_time - start_time) * 1000, 2)
    
    if is_alive:
        print(f"✅ {ip} is reachable (Response time: {response_time}ms)")
    else:
        print(f"❌ {ip} is not reachable")

if __name__ == "__main__":
    main()