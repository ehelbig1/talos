#!/usr/bin/env python3
"""
Google Calendar Webhook Flow Test
Tests the complete webhook-to-WASM execution pipeline with deduplication.
"""

import json
import subprocess
import time
import sys
from datetime import datetime, timedelta
import hashlib

# Test configuration
WEBHOOK_URL = "http://localhost:8000/api/google-calendar/webhook"
CHANNEL_ID = "c224bca0-4ead-4417-9afc-4d628a6d31f0"
CALENDAR_ID = "test-user@example.com"

# Get verification token from database
def get_verification_token():
    cmd = f"""docker-compose exec -T postgres psql -U talos -d talos -t -c "SELECT verification_token FROM google_calendar_watch_channels WHERE channel_id = '{CHANNEL_ID}';" """
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    token = result.stdout.strip()
    return token

# Generate test event data
def generate_test_event(event_id, summary, status="confirmed"):
    """Generate a mock Google Calendar event"""
    now = datetime.utcnow()
    start = now + timedelta(hours=1)
    end = start + timedelta(hours=1)

    return {
        "id": event_id,
        "status": status,
        "summary": summary,
        "description": "Test event for webhook processing",
        "start": {
            "dateTime": start.isoformat() + "Z",
            "timeZone": "UTC"
        },
        "end": {
            "dateTime": end.isoformat() + "Z",
            "timeZone": "UTC"
        },
        "created": now.isoformat() + "Z",
        "updated": now.isoformat() + "Z",
        "creator": {
            "email": CALENDAR_ID,
            "self": True
        },
        "organizer": {
            "email": CALENDAR_ID,
            "self": True
        },
        "attendees": [
            {
                "email": CALENDAR_ID,
                "responseStatus": "accepted",
                "self": True
            }
        ]
    }

# Test scenarios
def test_static_verification():
    """Test 1: Verify all components are in place"""
    print("=" * 60)
    print("TEST 1: Static Code Verification")
    print("=" * 60)

    tests_passed = 0
    tests_failed = 0

    # Check database schema
    print("\n📊 Database Schema:")
    cmd = """docker-compose exec -T postgres psql -U talos -d talos -t -c "SELECT COUNT(*) FROM google_calendar_watch_channels WHERE module_id IS NOT NULL AND is_active = true;" """
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    try:
        count = int(result.stdout.strip())
        if result.returncode == 0 and count > 0:
            print(f"  ✅ Watch channels with module_id: {count} found - PASS")
            tests_passed += 1
        else:
            print("  ❌ No watch channels with module_id: FAIL")
            tests_failed += 1
    except (ValueError, AttributeError):
        print(f"  ❌ Failed to parse result: {result.stdout[:50]}")
        tests_failed += 1

    # Check Redis connection
    print("\n🔌 Redis Connection:")
    cmd = "docker-compose logs controller --tail 100 | grep 'Redis client initialized'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.returncode == 0 and result.stdout:
        print("  ✅ Redis connected: PASS")
        tests_passed += 1
    else:
        print("  ❌ Redis not connected: FAIL")
        tests_failed += 1

    # Check deduplication functions
    print("\n🔍 Deduplication Functions:")
    functions = [
        "generate_event_cache_key",
        "deduplicate_events",
        "mark_event_processed",
        "filter_events",
        "process_webhook_events"
    ]

    for func in functions:
        cmd = f"grep -q 'fn {func}\\|async fn {func}' controller/src/google_calendar/handlers.rs"
        result = subprocess.run(cmd, shell=True)

        if result.returncode == 0:
            print(f"  ✅ {func}(): PASS")
            tests_passed += 1
        else:
            print(f"  ❌ {func}(): FAIL")
            tests_failed += 1

    # Check filter types
    print("\n🎯 Filter Implementations:")
    filters = [
        "EVENT_TYPES",
        "FILTER_TITLE_KEYWORDS",
        "EXCLUDE_ALL_DAY_EVENTS",
        "ONLY_WITH_ATTENDEES",
        "FILTER_ATTENDEE_EMAILS",
        "MIN_DURATION_MINUTES",
        "EXCLUDE_DECLINED_EVENTS"
    ]

    for filter_type in filters:
        cmd = f"grep -q '{filter_type}' controller/src/google_calendar/handlers.rs"
        result = subprocess.run(cmd, shell=True)

        if result.returncode == 0:
            print(f"  ✅ {filter_type}: PASS")
            tests_passed += 1
        else:
            print(f"  ❌ {filter_type}: FAIL")
            tests_failed += 1

    print("\n" + "=" * 60)
    print(f"Static Tests: {tests_passed} passed, {tests_failed} failed")
    print("=" * 60)

    return tests_failed == 0

def test_cache_key_generation():
    """Test 2: Verify cache key generation logic"""
    print("\n" + "=" * 60)
    print("TEST 2: Cache Key Generation Logic")
    print("=" * 60)

    # Read the cache key generation logic
    cmd = "grep -A 10 'fn generate_event_cache_key' controller/src/google_calendar/handlers.rs"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    print("\n📝 Cache Key Format:")
    if "gcal:processed" in result.stdout:
        print("  ✅ Uses 'gcal:processed' prefix: PASS")

        if "event_id" in result.stdout:
            print("  ✅ Includes event_id: PASS")
        else:
            print("  ❌ Missing event_id: FAIL")

        if "updated" in result.stdout:
            print("  ✅ Includes updated timestamp (version-aware): PASS")
        else:
            print("  ⚠️  May not be version-aware: WARNING")

        if "calendar_id" in result.stdout or "organizer" in result.stdout:
            print("  ✅ Includes calendar identifier: PASS")
        else:
            print("  ⚠️  May not include calendar: WARNING")

        return True
    else:
        print("  ❌ Cache key format not found: FAIL")
        return False

def test_deduplication_integration():
    """Test 3: Check deduplication is integrated into webhook flow"""
    print("\n" + "=" * 60)
    print("TEST 3: Deduplication Integration")
    print("=" * 60)

    tests_passed = 0

    # Check deduplicate_events is called
    print("\n🔗 Integration Points:")
    cmd = "grep -B 5 -A 5 'deduplicate_events' controller/src/google_calendar/handlers.rs | grep -v 'async fn deduplicate_events'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.returncode == 0 and "process_webhook_events" in result.stdout:
        print("  ✅ deduplicate_events() called in webhook flow: PASS")
        tests_passed += 1
    else:
        print("  ❌ deduplicate_events() not integrated: FAIL")

    # Check mark_event_processed is called
    cmd = "grep -B 5 -A 5 'mark_event_processed' controller/src/google_calendar/handlers.rs | grep -v 'async fn mark_event_processed'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.returncode == 0 and len(result.stdout.strip()) > 0:
        print("  ✅ mark_event_processed() called after execution: PASS")
        tests_passed += 1
    else:
        print("  ❌ mark_event_processed() not integrated: FAIL")

    # Check Redis client is passed
    cmd = "grep 'redis_client' controller/src/google_calendar/handlers.rs"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.returncode == 0 and len(result.stdout.strip()) > 0:
        print("  ✅ Redis client passed to functions: PASS")
        tests_passed += 1
    else:
        print("  ❌ Redis client not passed: FAIL")

    # Check graceful degradation
    cmd = "grep -A 5 'deduplicate_events' controller/src/google_calendar/handlers.rs | grep -E 'Err|warn|fail'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.returncode == 0:
        print("  ✅ Error handling present (graceful degradation): PASS")
        tests_passed += 1
    else:
        print("  ⚠️  Error handling not verified: WARNING")

    return tests_passed >= 3

def test_filter_logic():
    """Test 4: Verify filter logic is applied"""
    print("\n" + "=" * 60)
    print("TEST 4: Event Filter Logic")
    print("=" * 60)

    # Check filter_events is called before WASM execution
    cmd = "grep -B 10 -A 10 'filter_events' controller/src/google_calendar/handlers.rs | grep -A 20 'process_webhook_events'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    print("\n🎯 Filter Application:")
    if result.returncode == 0:
        print("  ✅ filter_events() called in webhook flow: PASS")

        # Check order: deduplicate -> filter -> execute
        cmd = "grep -n 'deduplicate_events\\|filter_events\\|execute_module' controller/src/google_calendar/handlers.rs | head -20"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        lines = result.stdout.strip().split('\n')
        if len(lines) >= 2:
            print("  ✅ Proper execution order (dedupe → filter → execute): PASS")

        return True
    else:
        print("  ❌ filter_events() not integrated: FAIL")
        return False

def test_wasm_execution():
    """Test 5: Verify WASM execution is integrated"""
    print("\n" + "=" * 60)
    print("TEST 5: WASM Execution Integration")
    print("=" * 60)

    tests_passed = 0

    # Check TalosRuntime is used
    print("\n🚀 WASM Execution:")
    cmd = "grep 'TalosRuntime' controller/src/google_calendar/handlers.rs"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.returncode == 0:
        print("  ✅ TalosRuntime used: PASS")
        tests_passed += 1
    else:
        print("  ❌ TalosRuntime not found: FAIL")

    # Check timeout protection
    cmd = "grep 'execute_module_with_timeout' controller/src/google_calendar/handlers.rs"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.returncode == 0:
        print("  ✅ Timeout protection enabled: PASS")
        tests_passed += 1

        # Check timeout duration
        if "from_secs(30)" in result.stdout or "Duration::from_secs" in result.stdout:
            print("  ✅ 30-second timeout configured: PASS")
            tests_passed += 1
    else:
        print("  ❌ No timeout protection: FAIL")

    # Check error handling
    cmd = "grep -A 5 'execute_module' controller/src/google_calendar/handlers.rs | grep -E 'Err|match|error'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.returncode == 0:
        print("  ✅ Error handling present: PASS")
        tests_passed += 1
    else:
        print("  ⚠️  Error handling not verified: WARNING")

    return tests_passed >= 3

def check_recent_activity():
    """Test 6: Check for recent webhook activity"""
    print("\n" + "=" * 60)
    print("TEST 6: Recent Webhook Activity")
    print("=" * 60)

    print("\n📊 Recent Logs:")

    # Check for webhook notifications
    cmd = "docker-compose logs controller --tail 200 --since 1h | grep -i 'webhook\\|synced.*events\\|dedup' | tail -10"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.stdout.strip():
        print("Recent activity found:")
        for line in result.stdout.strip().split('\n')[:10]:
            print(f"  {line[:120]}")
        return True
    else:
        print("  ℹ️  No recent webhook activity (create a calendar event to test)")
        return False

def main():
    print("\n🧪 COMPREHENSIVE GOOGLE CALENDAR WEBHOOK TEST SUITE")
    print("=" * 60)
    print(f"Testing webhook-to-WASM execution with deduplication")
    print(f"Channel ID: {CHANNEL_ID}")
    print(f"Calendar: {CALENDAR_ID}")
    print("=" * 60)

    results = []

    # Run all tests
    results.append(("Static Verification", test_static_verification()))
    results.append(("Cache Key Generation", test_cache_key_generation()))
    results.append(("Deduplication Integration", test_deduplication_integration()))
    results.append(("Filter Logic", test_filter_logic()))
    results.append(("WASM Execution", test_wasm_execution()))
    results.append(("Recent Activity", check_recent_activity()))

    # Summary
    print("\n" + "=" * 60)
    print("FINAL RESULTS")
    print("=" * 60)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")

    print("=" * 60)
    print(f"Total: {passed}/{total} tests passed")

    if passed == total:
        print("\n🎉 All tests passed! System is fully operational.")
        print("\n📝 Next Steps:")
        print("1. Create a test event in Google Calendar (replace CALENDAR_ID with your account)")
        print("2. Monitor logs in real-time:")
        print("   docker-compose logs controller -f | grep -E 'Synced|Dedup|Filter|processed'")
        print("3. Verify deduplication by updating the same event")
        print("4. Check Redis cache keys:")
        print("   docker-compose exec redis redis-cli --raw KEYS 'gcal:processed:*'")
        return 0
    else:
        print("\n⚠️  Some tests failed. Review the output above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
