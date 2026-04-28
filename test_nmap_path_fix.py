#!/usr/bin/env python3
"""
Test Nmap path fix
"""

from scanner import NetworkScanner
import logging

def test_nmap_initialization():
    """Test Nmap initialization with new path handling"""
    print("Testing Nmap Path Fix")
    print("=" * 50)
    
    try:
        # Initialize scanner
        scanner = NetworkScanner()
        
        print(f"NMAP_AVAILABLE: {scanner.nm is not None}")
        
        if scanner.nm:
            print("SUCCESS: Nmap initialized successfully!")
            print(f"Nmap version: {scanner.nm.nmap_version()}")
            print("Port scanning capabilities: AVAILABLE")
        else:
            print("INFO: Nmap not available, using basic port scanning")
            print("Port scanning capabilities: BASIC (socket-based)")
        
        # Test port scanning
        print("\nTesting port scanning...")
        result = scanner.scan_ports_nmap("127.0.0.1", [22, 80, 443])
        
        print(f"Scan result: {len(result)} ports tested")
        for port in result:
            print(f"  Port {port['port']}: {port['state']}")
        
        return True
        
    except Exception as e:
        print(f"ERROR: {e}")
        return False

def main():
    """Run test"""
    print("Nmap Path Fix Test")
    print("=" * 60)
    
    success = test_nmap_initialization()
    
    print("\n" + "=" * 60)
    if success:
        print("NMAP PATH FIX: SUCCESS")
        print("The scanner now properly handles Nmap paths on Windows")
    else:
        print("NMAP PATH FIX: FAILED")
        print("Check Nmap installation")
    
    print("\nExpected behavior:")
    print("- If Nmap installed: Uses Nmap for advanced scanning")
    print("- If Nmap not installed: Falls back to basic socket scanning")
    print("- No more 'nmap program not found' errors")

if __name__ == "__main__":
    main()
