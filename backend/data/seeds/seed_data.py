from backend.app.core.database import SessionLocal
from backend.app.models.database import *

def create_seed_data():
    db = SessionLocal()
    try:
        # Check if we already have data
        if db.query(Scenario).first():
            return
        
        # Create a basic scenario
        scenario = Scenario(
            id="basic_test_scenario",
            name="Basic Test Scenario",
            description="A simple test scenario for validating the canonical graph"
        )
        db.add(scenario)
        
        # Create assets
        web_server = Asset(
            id="asset-web-01",
            name="Public Web Server",
            type=AssetType.WEB_SERVER,
            criticality=8.0,
            environment=Environment.PRODUCTION,
            network_zone=NetworkZone.DMZ,
            is_entry_point=True,
            is_crown_jewel=False,
            owner="IT Team",
            ip_address="203.0.113.1"
        )
        
        app_server = Asset(
            id="asset-app-01",
            name="Application Server",
            type=AssetType.APP_SERVER,
            criticality=9.0,
            environment=Environment.PRODUCTION,
            network_zone=NetworkZone.APP_TIER,
            is_entry_point=False,
            is_crown_jewel=False,
            owner="IT Team",
            ip_address="10.0.1.10"
        )
        
        database_server = Asset(
            id="asset-db-01",
            name="Primary Database",
            type=AssetType.DATABASE,
            criticality=10.0,
            environment=Environment.PRODUCTION,
            network_zone=NetworkZone.DB_TIER,
            is_entry_point=False,
            is_crown_jewel=True,
            owner="DBA Team",
            ip_address="10.0.2.10"
        )
        
        db.add_all([web_server, app_server, database_server])
        
        # Create vulnerabilities
        vuln1 = Vulnerability(
            id="vuln-cve-2023-12345",
            cve_id="CVE-2023-12345",
            title="Remote Code Execution in Web Server",
            description="A critical remote code execution vulnerability in the web server software",
            cvss_score=9.8,
            severity=VulnerabilitySeverity.CRITICAL,
            epss_score=0.85,
            known_exploited=True,
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE
        )
        
        vuln2 = Vulnerability(
            id="vuln-cve-2023-67890",
            cve_id="CVE-2023-67890",
            title="SQL Injection in Application Server",
            description="An SQL injection vulnerability in the application server",
            cvss_score=8.2,
            severity=VulnerabilitySeverity.HIGH,
            epss_score=0.65,
            known_exploited=False,
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.LOW,
            user_interaction=UserInteraction.NONE
        )
        
        db.add_all([vuln1, vuln2])
        
        # Create findings
        finding1 = Finding(
            id="finding-01",
            asset_id="asset-web-01",
            vulnerability_id="vuln-cve-2023-12345",
            port=443,
            service_name="HTTPS",
            status=FindingStatus.ACTIVE
        )
        
        finding2 = Finding(
            id="finding-02",
            asset_id="asset-app-01",
            vulnerability_id="vuln-cve-2023-67890",
            port=8080,
            service_name="HTTP",
            status=FindingStatus.ACTIVE
        )
        
        db.add_all([finding1, finding2])
        
        # Create edges (attack transitions)
        edge1 = Edge(
            id="edge-web-to-finding1",
            source_id="asset-web-01",
            target_id="finding-01",
            edge_type=EdgeType.CAN_REACH,
            port=443,
            protocol="TCP",
            traversal_cost=1.0,
            probability=0.9
        )
        
        edge2 = Edge(
            id="edge-finding1-to-app",
            source_id="finding-01",
            target_id="asset-app-01",
            edge_type=EdgeType.EXPLOITS,
            port=8080,
            protocol="TCP",
            traversal_cost=2.0,
            probability=0.7,
            finding_id="finding-01"
        )
        
        edge3 = Edge(
            id="edge-app-to-finding2",
            source_id="asset-app-01",
            target_id="finding-02",
            edge_type=EdgeType.CAN_REACH,
            port=8080,
            protocol="TCP",
            traversal_cost=1.0,
            probability=0.8
        )
        
        edge4 = Edge(
            id="edge-finding2-to-db",
            source_id="finding-02",
            target_id="asset-db-01",
            edge_type=EdgeType.EXPLOITS,
            port=1433,
            protocol="TCP",
            traversal_cost=2.5,
            probability=0.6,
            finding_id="finding-02"
        )
        
        edge5 = Edge(
            id="edge-direct-web-to-db",
            source_id="asset-web-01",
            target_id="asset-db-01",
            edge_type=EdgeType.CAN_REACH,
            port=1433,
            protocol="TCP",
            traversal_cost=3.0,
            probability=0.3
        )
        
        db.add_all([edge1, edge2, edge3, edge4, edge5])
        
        db.commit()
        print("Seed data created successfully!")
        
    except Exception as e:
        db.rollback()
        print(f"Error creating seed data: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    create_seed_data()
