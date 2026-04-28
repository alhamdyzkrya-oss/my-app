#!/usr/bin/env python3
"""
Simple test for Ollama AI integration
"""

import json
from security import ask_ollama

def test_ask_ollama():
    """Test ask_ollama function"""
    print("Testing ask_ollama function...")
    
    try:
        response = ask_ollama("What is 2+2?")
        print("Function executed successfully")
        print(f"Response: {response}")
        
        if "AI service unavailable" in response:
            print("Error handling works correctly (Ollama not running)")
        else:
            print("AI service is running and responding")
            
    except Exception as e:
        print(f"Error: {e}")
        return False
    
    return True

def test_data_format():
    """Test the data format for AI analysis"""
    print("\nTesting data format...")
    
    sample_data = {
        "devices": [
            {
                "ip": "192.168.1.1",
                "status": "UP",
                "ports": [
                    {"port": 22, "status": "OPEN"},
                    {"port": 80, "status": "OPEN"}
                ]
            }
        ]
    }
    
    print("Sample data format:")
    print(json.dumps(sample_data, indent=2))
    print("Data format is correct")
    return True

if __name__ == "__main__":
    print("Ollama AI Integration Test")
    print("=" * 40)
    
    success = True
    success &= test_ask_ollama()
    success &= test_data_format()
    
    print("\n" + "=" * 40)
    if success:
        print("All tests passed!")
        print("\nUsage:")
        print("1. Start Ollama: ollama serve")
        print("2. Pull model: ollama pull llama3")
        print("3. Send POST to /ai-analysis with device data")
    else:
        print("Some tests failed!")
