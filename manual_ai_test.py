#!/usr/bin/env python3
"""
Manual test for AI button functionality
"""

import requests
import json

def test_ai_manually():
    print("=== MANUAL AI TEST ===")
    
    # Test 1: Check if Flask app is running
    try:
        response = requests.get('http://localhost:5000/dashboard', timeout=5)
        print(f"Dashboard accessible: {response.status_code == 200}")
    except:
        print("ERROR: Flask app not running on localhost:5000")
        return
    
    # Test 2: Check if we can get devices without auth
    print("\nTesting device API...")
    try:
        response = requests.get('http://localhost:5000/api/equipments/status', 
                              headers={'X-Requested-With': 'XMLHttpRequest'}, 
                              timeout=5)
        print(f"Device API status: {response.status_code}")
        
        if response.status_code == 302:
            print("Device API requires authentication (redirect to login)")
        elif response.status_code == 200:
            devices = response.json()
            print(f"Found {len(devices)} devices")
            if devices:
                print(f"First device: {devices[0]}")
        else:
            print("No devices found")
    except Exception as e:
        print(f"Device API error: {e}")
    
    # Test 3: Try AI endpoint without auth (should fail)
    print("\nTesting AI endpoint without auth...")
    try:
        test_data = {
            'devices': [
                {'ip': '192.168.1.1', 'status': 'UP', 'ports': [{'port': 22, 'status': 'OPEN'}]}
            ]
        }
        
        response = requests.post('http://localhost:5000/ai-analysis',
                               json=test_data,
                               headers={'X-Requested-With': 'XMLHttpRequest'},
                               timeout=30)
        print(f"AI endpoint status: {response.status_code}")
        
        if response.status_code == 302:
            print("AI endpoint requires authentication (expected)")
        elif response.status_code == 200:
            data = response.json()
            print("AI endpoint working without auth (unexpected)")
            print(f"Analysis length: {len(data.get('analysis', ''))}")
        else:
            print(f"Unexpected response: {response.status_code}")
            
    except Exception as e:
        print(f"AI endpoint error: {e}")
    
    # Test 4: Try test AI endpoint (should work)
    print("\nTesting test AI endpoint...")
    try:
        response = requests.post('http://localhost:5000/test-ai-analysis',
                               json=test_data,
                               headers={'X-Requested-With': 'XMLHttpRequest'},
                               timeout=30)
        print(f"Test AI endpoint status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print("Test AI endpoint working!")
            print(f"Analysis length: {len(data.get('analysis', ''))}")
            print("Sample analysis:")
            print(data.get('analysis', '')[:200] + "...")
        else:
            print(f"Test AI endpoint failed: {response.status_code}")
            print(response.text)
            
    except Exception as e:
        print(f"Test AI endpoint error: {e}")
    
    # Test 5: Check Ollama directly
    print("\nTesting Ollama directly...")
    try:
        ollama_data = {
            "model": "llama3.2",
            "prompt": "What is 2+2?",
            "stream": False
        }
        
        response = requests.post('http://localhost:11434/api/generate',
                               json=ollama_data,
                               timeout=30)
        print(f"Ollama status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print("Ollama working!")
            print(f"Response: {result.get('response', 'No response')}")
        else:
            print(f"Ollama error: {response.status_code}")
            
    except Exception as e:
        print(f"Ollama error: {e}")
    
    print("\n=== RECOMMENDATIONS ===")
    print("1. If test AI endpoint works but dashboard doesn't, the issue is in JavaScript")
    print("2. If device API requires auth, make sure you're logged in")
    print("3. Check browser console for JavaScript errors")
    print("4. Make sure Ollama is running: ollama serve")

if __name__ == "__main__":
    test_ai_manually()
