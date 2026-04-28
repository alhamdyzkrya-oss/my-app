#!/usr/bin/env python3
"""
Test AI button functionality
"""

from app import app
import json

def test_ai_button_route():
    """Test the AI button route"""
    print("Testing AI Button Route")
    print("=" * 50)
    
    with app.test_client() as client:
        print("\n1. Testing POST /generate-ai-report...")
        
        response = client.post('/generate-ai-report', 
                              data=json.dumps({}),
                              content_type='application/json')
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        
        if response.status_code == 302:
            print("REDIRECT: User needs to login (expected for test)")
            print("Login required: YES")
        elif response.status_code == 200:
            try:
                data = response.get_json()
                if 'result' in data:
                    print("SUCCESS: AI response generated!")
                    print(f"Response keys: {list(data.keys())}")
                else:
                    print("ERROR: 'result' field missing")
                    print(f"Available fields: {list(data.keys())}")
            except:
                print("ERROR: Invalid JSON response")
        else:
            print(f"ERROR: Unexpected status code {response.status_code}")
            print(f"Response: {response.data.decode()[:200]}...")
        
        print("\n2. Testing GET /dashboard (to check template)...")
        response = client.get('/dashboard')
        print(f"Dashboard status: {response.status_code}")
        
        if response.status_code == 200:
            print("SUCCESS: Dashboard accessible")
            # Check if AI button exists in template
            if 'ai-analysis-btn' in response.data.decode():
                print("SUCCESS: AI button found in template")
            else:
                print("ERROR: AI button NOT found in template")
        elif response.status_code == 302:
            print("REDIRECT: Login required for dashboard")
        else:
            print(f"ERROR: Dashboard returned {response.status_code}")

def main():
    """Run test"""
    print("AI Button Debug Test")
    print("=" * 60)
    
    test_ai_button_route()
    
    print("\n" + "=" * 60)
    print("DEBUG CHECKLIST:")
    print("1. Open browser: http://localhost:5000")
    print("2. Login to dashboard")
    print("3. Press F12 for console")
    print("4. Click 'Generate AI Report' button")
    print("5. Check console for DEBUG messages")
    print("\nExpected console output:")
    print("- DEBUG: AI button found!")
    print("- DEBUG: AI button clicked!")
    print("- DEBUG: Starting AI analysis...")
    print("- DEBUG: AI response status: 200")
    print("- DEBUG: AI response data: {...}")

if __name__ == "__main__":
    main()
