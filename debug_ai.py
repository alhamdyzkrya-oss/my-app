#!/usr/bin/env python3
"""
Debug script to identify AI button issues
"""

def test_ai_endpoint():
    print("=== AI ENDPOINT DEBUG ===")
    
    # Test 1: Check if route is accessible
    from app import app
    import json
    
    print("\n1. Testing AI endpoint directly...")
    
    with app.test_client() as client:
        # Create test session (simulate logged in user)
        with client.session_transaction() as sess:
            sess['_user_id'] = '1'
            sess['_fresh'] = True
        
        # Test with sample data
        test_data = {
            'devices': [
                {
                    'ip': '192.168.1.1',
                    'status': 'UP',
                    'ports': [
                        {'port': 22, 'status': 'OPEN'},
                        {'port': 80, 'status': 'OPEN'}
                    ]
                }
            ]
        }
        
        response = client.post('/ai-analysis', 
                              json=test_data,
                              headers={'X-Requested-With': 'XMLHttpRequest'})
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            data = response.get_json()
            print("SUCCESS: AI endpoint working")
            print(f"Response: {data}")
        elif response.status_code == 302:
            print("REDIRECT: Authentication required")
            print(f"Location: {response.location}")
        else:
            print(f"ERROR: {response.status_code}")
            print(f"Response: {response.get_data(as_text=True)}")
    
    # Test 2: Check if Ollama is working
    print("\n2. Testing Ollama connection...")
    try:
        from security import ask_ollama
        response = ask_ollama("Test: What is 1+1?")
        if "AI service unavailable" in response:
            print("ERROR: Ollama not accessible")
        else:
            print("SUCCESS: Ollama working")
            print(f"Sample response: {response[:50]}...")
    except Exception as e:
        print(f"ERROR: {e}")
    
    # Test 3: Check dashboard template
    print("\n3. Checking dashboard template...")
    try:
        with open('templates/dashboard.html', 'r') as f:
            content = f.read()
        
        # Check for essential elements
        checks = {
            'generateAIAnalysis function': 'function generateAIAnalysis()' in content,
            'AI button': 'id="ai-analysis-btn"' in content,
            'Loading div': 'id="ai-analysis-loading"' in content,
            'Result div': 'id="ai-analysis-result"' in content,
            'Error div': 'id="ai-analysis-error"' in content
        }
        
        for check, result in checks.items():
            status = "OK" if result else "MISSING"
            print(f"  {check}: {status}")
            
    except Exception as e:
        print(f"ERROR: {e}")
    
    print("\n=== DEBUG COMPLETE ===")

if __name__ == "__main__":
    test_ai_endpoint()
