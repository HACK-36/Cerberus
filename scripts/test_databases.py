"""
Test script to verify Redis and PostgreSQL connectivity
"""
import sys
import os

# Add parent directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from shared.database import RedisClient, PostgresClient


def test_redis():
    """Test Redis connectivity and operations"""
    print("\n=== Testing Redis ===")
    
    try:
        redis = RedisClient(url="redis://localhost:6379")
        
        # Test ping
        if redis.ping():
            print("✅ Redis PING: OK")
        else:
            print("❌ Redis PING: Failed")
            return False
        
        # Test set/get
        redis.set("test_key", "test_value", ttl=60)
        value = redis.get("test_key")
        if value == "test_value":
            print("✅ Redis SET/GET: OK")
        else:
            print("❌ Redis SET/GET: Failed")
            return False
        
        # Test JSON storage
        test_data = {"name": "Cerberus", "version": "1.0", "features": ["ML", "Honeypot"]}
        redis.set("test_json", test_data, ttl=60)
        retrieved = redis.get("test_json", as_json=True)
        if retrieved == test_data:
            print("✅ Redis JSON Storage: OK")
        else:
            print("❌ Redis JSON Storage: Failed")
            return False
        
        # Test hash operations
        redis.hset("test_hash", "field1", "value1")
        redis.hset("test_hash", "field2", {"nested": "data"})
        hash_value = redis.hget("test_hash", "field1")
        hash_json = redis.hget("test_hash", "field2", as_json=True)
        if hash_value == "value1" and hash_json.get("nested") == "data":
            print("✅ Redis HASH Operations: OK")
        else:
            print("❌ Redis HASH Operations: Failed")
            return False
        
        # Test list operations
        redis.rpush("test_list", "item1", "item2", {"key": "value"})
        list_items = redis.lrange("test_list", 0, -1, as_json=False)
        if len(list_items) == 3:
            print("✅ Redis LIST Operations: OK")
        else:
            print("❌ Redis LIST Operations: Failed")
            return False
        
        # Test counter
        redis.incr("test_counter", 5)
        counter = redis.get("test_counter")
        if counter == "5":
            print("✅ Redis COUNTER Operations: OK")
        else:
            print("❌ Redis COUNTER Operations: Failed")
            return False
        
        # Cleanup
        redis.delete("test_key", "test_json", "test_hash", "test_list", "test_counter")
        
        print("\n✅ Redis: All tests passed!")
        return True
        
    except Exception as e:
        print(f"\n❌ Redis: Error - {e}")
        return False


def test_postgres():
    """Test PostgreSQL connectivity and operations"""
    print("\n=== Testing PostgreSQL ===")
    
    try:
        pg = PostgresClient(url="postgresql://cerberus:cerberus_password@localhost:5432/cerberus")
        
        # Test ping
        if pg.ping():
            print("✅ PostgreSQL PING: OK")
        else:
            print("❌ PostgreSQL PING: Failed")
            return False
        
        # Test schema exists
        result = pg.fetch_one("SELECT schema_name FROM information_schema.schemata WHERE schema_name = 'cerberus'")
        if result:
            print("✅ PostgreSQL Schema 'cerberus': Exists")
        else:
            print("❌ PostgreSQL Schema 'cerberus': Not found")
            return False
        
        # Test tables exist
        tables = [
            'events',
            'waf_rules',
            'attacker_profiles',
            'simulations',
            'captures',
            'metrics'
        ]
        
        for table in tables:
            query = """
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'cerberus' 
                    AND table_name = %s
                )
            """
            result = pg.fetch_one(query, (table,))
            if result and result[0]:
                print(f"✅ Table 'cerberus.{table}': Exists")
            else:
                print(f"❌ Table 'cerberus.{table}': Not found")
                return False
        
        # Test insert
        test_event_id = "test_event_123"
        pg.execute(
            "INSERT INTO cerberus.events (event_id, source, event_type, data) VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING",
            (test_event_id, "test", "test_event", '{"test": true}')
        )
        print("✅ PostgreSQL INSERT: OK")
        
        # Test select
        result = pg.fetch_dict(
            "SELECT * FROM cerberus.events WHERE event_id = %s",
            (test_event_id,)
        )
        if result and len(result) > 0:
            print("✅ PostgreSQL SELECT: OK")
        else:
            print("❌ PostgreSQL SELECT: Failed")
            return False
        
        # Test update
        pg.execute(
            "UPDATE cerberus.events SET data = %s WHERE event_id = %s",
            ('{"test": false, "updated": true}', test_event_id)
        )
        print("✅ PostgreSQL UPDATE: OK")
        
        # Test views
        recent_attacks = pg.fetch_dict("SELECT * FROM cerberus.recent_attacks LIMIT 5")
        print(f"✅ View 'recent_attacks': {len(recent_attacks)} rows")
        
        rule_effectiveness = pg.fetch_dict("SELECT * FROM cerberus.rule_effectiveness LIMIT 5")
        print(f"✅ View 'rule_effectiveness': {len(rule_effectiveness)} rows")
        
        # Cleanup
        pg.execute("DELETE FROM cerberus.events WHERE event_id = %s", (test_event_id,))
        
        # Show database stats
        stats = pg.fetch_dict("""
            SELECT 
                schemaname,
                tablename,
                pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
            FROM pg_tables
            WHERE schemaname = 'cerberus'
            ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
        """)
        
        print("\n📊 Database Statistics:")
        for stat in stats:
            print(f"   {stat['tablename']}: {stat['size']}")
        
        print("\n✅ PostgreSQL: All tests passed!")
        return True
        
    except Exception as e:
        print(f"\n❌ PostgreSQL: Error - {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all database tests"""
    print("=" * 60)
    print("Cerberus Database Connectivity Test")
    print("=" * 60)
    
    redis_ok = test_redis()
    postgres_ok = test_postgres()
    
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    print(f"Redis: {'✅ PASS' if redis_ok else '❌ FAIL'}")
    print(f"PostgreSQL: {'✅ PASS' if postgres_ok else '❌ FAIL'}")
    print("=" * 60)
    
    if redis_ok and postgres_ok:
        print("\n🎉 All database tests passed!")
        return 0
    else:
        print("\n⚠️  Some database tests failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
