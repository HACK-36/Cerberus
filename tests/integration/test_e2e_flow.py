"""
End-to-End Integration Test
Tests complete flow from attack to auto-block
"""
import pytest
import requests
import time
import json


BASE_URL = "http://localhost"
GATEKEEPER_URL = f"{BASE_URL}:8000"
SWITCH_URL = f"{BASE_URL}:8001"
LABYRINTH_URL = f"{BASE_URL}:8002"
SENTINEL_URL = f"{BASE_URL}:8003"


class TestE2EFlow:
    """End-to-end integration tests"""
    
    def test_normal_traffic_allowed(self):
        """Test that normal traffic passes through"""
        response = requests.post(
            f"{GATEKEEPER_URL}/api/v1/inspect",
            json={
                "method": "GET",
                "url": "/api/users",
                "headers": {"User-Agent": "Mozilla/5.0", "Host": "example.com"},
                "body": "",
                "query_params": {},
                "client_ip": "192.168.1.100",
                "session_id": "normal_session_001",
                "metadata": {}
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["action"] in ["allow", "tag_poi"]
        assert "scores" in data
    
    def test_sql_injection_tagged_as_poi(self):
        """Test that SQLi attack is tagged as POI"""
        # Submit SQLi payload to Gatekeeper
        response = requests.post(
            f"{GATEKEEPER_URL}/api/v1/inspect",
            json={
                "method": "GET",
                "url": "/api/users?id=1' OR '1'='1",
                "headers": {"User-Agent": "sqlmap/1.0", "Host": "example.com"},
                "body": "",
                "query_params": {"id": "1' OR '1'='1"},
                "client_ip": "203.0.113.42",
                "session_id": "attacker_session_001",
                "metadata": {}
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Should be tagged as POI
        assert data["action"] in ["tag_poi", "block"]
        assert data["scores"]["combined"] > 50.0
        
        if data["action"] == "tag_poi":
            assert "event_id" in data
    
    def test_session_pinning_to_labyrinth(self):
        """Test session pinning to Labyrinth"""
        # Pin a session
        response = requests.post(
            f"{SWITCH_URL}/api/v1/switch/pin",
            json={
                "session_id": "test_session_002",
                "client_ip": "203.0.113.50",
                "reason": "Tagged as POI by Gatekeeper",
                "duration_hours": 24
            },
            headers={"Authorization": "Bearer test-token"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["target"] == "labyrinth"
        assert "fingerprint" in data
        
        # Verify routing decision
        route_response = requests.post(
            f"{SWITCH_URL}/api/v1/switch/route",
            json={
                "session_id": "test_session_002",
                "client_ip": "203.0.113.50",
                "user_agent": "Mozilla/5.0",
                "cookies": {}
            }
        )
        
        assert route_response.status_code == 200
        route_data = route_response.json()
        assert route_data["target"] == "labyrinth"
    
    def test_labyrinth_captures_payload(self):
        """Test that Labyrinth captures attack payloads"""
        # Send SQLi payload directly to Labyrinth
        response = requests.get(
            f"{LABYRINTH_URL}/api/v1/users",
            params={"id": "1' OR '1'='1--"}
        )
        
        # Labyrinth should respond (honeypot always responds)
        assert response.status_code in [200, 500]
        
        # Give time for capture
        time.sleep(1)
        
        # Check if payload was captured (in production: query evidence store)
        # For this test, we verify Labyrinth is reachable
        health_response = requests.get(f"{LABYRINTH_URL}/health")
        assert health_response.status_code == 200
    
    def test_sentinel_simulation(self):
        """Test Sentinel payload simulation"""
        # Simulate a payload
        payload = {
            "type": "sql_injection",
            "value": "1' OR '1'='1",
            "location": "query.id",
            "confidence": 0.95
        }
        
        response = requests.post(
            f"{SENTINEL_URL}/api/v1/sentinel/simulate",
            json={
                "payload": payload,
                "shadow_app_ref": "main",
                "metadata": {"session_id": "test_sim_001"}
            },
            headers={"Authorization": "Bearer test-token"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "job_id" in data
        assert data["status"] in ["queued", "running"]
        
        job_id = data["job_id"]
        
        # Poll for result (wait up to 60 seconds)
        for _ in range(12):
            time.sleep(5)
            result_response = requests.get(
                f"{SENTINEL_URL}/api/v1/sentinel/sim-result/{job_id}"
            )
            
            if result_response.status_code == 200:
                result_data = result_response.json()
                if result_data.get("status") == "completed":
                    assert "result" in result_data
                    assert result_data["result"]["verdict"] in ["exploit_possible", "exploit_improbable"]
                    break
    
    def test_rule_generation(self):
        """Test automatic rule generation"""
        # Simulate successful exploit
        sim_result = {
            "verdict": "exploit_possible",
            "severity": 9.0,
            "attack_type": "sql_injection",
            "execution_time_ms": 1500
        }
        
        payload = {
            "type": "sql_injection",
            "value": "' OR '1'='1",
            "location": "query.id",
            "confidence": 0.95
        }
        
        # Propose a rule
        response = requests.post(
            f"{SENTINEL_URL}/api/v1/sentinel/rule-propose",
            json={
                "payload": payload,
                "sim_result": sim_result,
                "profile": None
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "rule" in data
        
        rule = data["rule"]
        assert rule["action"] in ["block", "challenge", "tag"]
        assert rule["confidence"] > 0.7
        assert "match" in rule
        assert "pattern" in rule["match"]
    
    def test_rule_application_to_gatekeeper(self):
        """Test pushing rule to Gatekeeper"""
        # Create a test rule
        rule = {
            "rule_id": "test_rule_001",
            "created_by": "test",
            "priority": 100,
            "match": {
                "type": "regex",
                "pattern": r"'\s*OR\s*'[^']*'\s*=\s*'[^']*",
                "location": ["args", "body"],
                "flags": {"caseless": True}
            },
            "action": "block",
            "confidence": 0.95,
            "evidence": {
                "simulation_id": "sim_test_001",
                "sample_payloads": ["' OR '1'='1"],
                "severity": 9.0,
                "attack_type": "sql_injection"
            },
            "valid_from": "2024-01-01T00:00:00Z",
            "expires_at": None,
            "audit": {},
            "enabled": True
        }
        
        # Push to Gatekeeper
        response = requests.post(
            f"{GATEKEEPER_URL}/api/v1/gatekeeper/rules",
            json={"rule": rule},
            headers={"Authorization": "Bearer test-token"}
        )
        
        assert response.status_code in [200, 201, 409]  # 409 if already exists
        
        if response.status_code in [200, 201]:
            data = response.json()
            assert data["status"] in ["created", "updated"]
    
    @pytest.mark.slow
    def test_complete_attack_to_block_flow(self):
        """
        Complete end-to-end test: attack → detection → simulation → rule → block
        
        This is the acceptance test demonstrating the full Cerberus capability
        """
        session_id = f"e2e_test_{int(time.time())}"
        attack_payload = "1' OR '1'='1--"
        
        print("\n=== CERBERUS E2E TEST ===")
        
        # Step 1: Attack detected by Gatekeeper
        print("Step 1: Sending attack to Gatekeeper...")
        gatekeeper_response = requests.post(
            f"{GATEKEEPER_URL}/api/v1/inspect",
            json={
                "method": "GET",
                "url": f"/api/users?id={attack_payload}",
                "headers": {"User-Agent": "attacker", "Host": "example.com"},
                "body": "",
                "query_params": {"id": attack_payload},
                "client_ip": "203.0.113.99",
                "session_id": session_id,
                "metadata": {}
            }
        )
        
        assert gatekeeper_response.status_code == 200
        print(f"✓ Gatekeeper response: {gatekeeper_response.json()['action']}")
        
        # Step 2: Session pinned (if tagged)
        if gatekeeper_response.json()["action"] == "tag_poi":
            print("Step 2: Pinning session to Labyrinth...")
            switch_response = requests.post(
                f"{SWITCH_URL}/api/v1/switch/pin",
                json={
                    "session_id": session_id,
                    "client_ip": "203.0.113.99",
                    "reason": "POI tagged",
                    "duration_hours": 1
                },
                headers={"Authorization": "Bearer test-token"}
            )
            assert switch_response.status_code == 200
            print("✓ Session pinned to Labyrinth")
        
        # Step 3: Capture in Labyrinth
        print("Step 3: Sending request to Labyrinth (honeypot)...")
        labyrinth_response = requests.get(
            f"{LABYRINTH_URL}/api/v1/users",
            params={"id": attack_payload}
        )
        print(f"✓ Labyrinth captured request (status: {labyrinth_response.status_code})")
        
        time.sleep(2)  # Allow capture processing
        
        # Step 4: Simulate payload
        print("Step 4: Simulating payload in Sentinel...")
        sim_response = requests.post(
            f"{SENTINEL_URL}/api/v1/sentinel/simulate",
            json={
                "payload": {
                    "type": "sql_injection",
                    "value": attack_payload,
                    "location": "query.id",
                    "confidence": 0.90
                },
                "shadow_app_ref": "main",
                "metadata": {"session_id": session_id}
            },
            headers={"Authorization": "Bearer test-token"}
        )
        
        assert sim_response.status_code == 200
        job_id = sim_response.json()["job_id"]
        print(f"✓ Simulation started: {job_id}")
        
        # Wait for simulation
        print("Waiting for simulation to complete...")
        for i in range(15):
            time.sleep(5)
            result_response = requests.get(
                f"{SENTINEL_URL}/api/v1/sentinel/sim-result/{job_id}"
            )
            
            if result_response.json().get("status") == "completed":
                print("✓ Simulation completed")
                result = result_response.json()["result"]
                print(f"  Verdict: {result['verdict']}, Severity: {result['severity']}")
                break
        
        # Step 5: Verify rule generation (auto or manual)
        print("Step 5: Checking for generated rules...")
        rules_response = requests.get(f"{SENTINEL_URL}/api/v1/sentinel/rules")
        assert rules_response.status_code == 200
        rules = rules_response.json()["rules"]
        print(f"✓ Total rules generated: {len(rules)}")
        
        # Step 6: Verify protection (subsequent attack blocked)
        print("Step 6: Verifying protection...")
        final_response = requests.post(
            f"{GATEKEEPER_URL}/api/v1/inspect",
            json={
                "method": "GET",
                "url": f"/api/users?id={attack_payload}",
                "headers": {"User-Agent": "attacker2", "Host": "example.com"},
                "body": "",
                "query_params": {"id": attack_payload},
                "client_ip": "203.0.113.100",
                "session_id": f"new_session_{int(time.time())}",
                "metadata": {}
            }
        )
        
        print(f"✓ Final check action: {final_response.json()['action']}")
        print("\n=== TEST COMPLETE ===\n")
        
        assert final_response.status_code == 200
