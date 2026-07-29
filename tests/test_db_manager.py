"""Database persistence, history, metadata, and retention tests."""
import sqlite3
from datetime import datetime, timedelta
import pytest
from core.models import Alert,Packet
from database.db_manager import DBManager
def test_session_packet_alert_and_csv_round_trip(tmp_path):
 db=DBManager(str(tmp_path/"netguard.db"));session=db.create_session("Ethernet");packet=Packet(datetime.now(),"10.0.0.1","10.0.0.2",50000,443,"HTTPS",120,"outbound");db.insert_packet_batch([packet],session);assert db.get_packets(session)[0].protocol=="HTTPS"
 alert=Alert(None,session,datetime.now(),"SUSPICIOUS_PORT","MEDIUM","10.0.0.1","10.0.0.2","Test",1,False);identifier=db.insert_alert(alert);assert db.find_recent_alert(session,"10.0.0.1","SUSPICIOUS_PORT",30).id==identifier;db.bump_alert_occurrence(identifier);db.acknowledge_alert(identifier);assert db.get_alerts(session)[0].occurrence_count==2 and db.get_alerts(session)[0].acknowledged
 output=tmp_path/"alerts.csv";db.export_csv(session,"alerts",str(output));assert output.read_text(encoding="utf-8-sig").startswith("First Detected,Last Detected,Severity,Alert")
 db.end_session(session,1,1,93);assert db.get_session_summary(session).final_security_score==93


def test_database_close_is_idempotent(tmp_path):
 db=DBManager(str(tmp_path/"netguard.db"));db.close();db.close()
 with pytest.raises(sqlite3.ProgrammingError):db.get_sessions()


def rich_packet(timestamp=None):
 return Packet(
  timestamp or datetime.now(),"10.0.0.10","203.0.113.20",50000,443,
  "HTTPS",120,"outbound","S",4,r"\Device\NPF_{TEST}",True,False,
  False,False,False,
 )


def test_packet_metadata_tcp_flags_and_connections_are_persisted(tmp_path):
 db=DBManager(str(tmp_path/"netguard.db"));session=db.create_session(r"\Device\NPF_{TEST}")
 first=rich_packet();second=rich_packet(first.timestamp+timedelta(seconds=1))
 db.insert_packet_batch([first,second],session)

 packets=db.get_packets(session);connection=db.get_connections(session)[0]
 assert packets[0].ip_version==4 and packets[0].interface==r"\Device\NPF_{TEST}"
 assert packets[0].src_is_local and packets[0].tcp_flags=="S"
 assert connection.packet_count==2 and connection.byte_count==240
 assert connection.src_port==50000 and connection.dst_port==443
 db.close()


def test_alert_evidence_fields_are_persisted(tmp_path):
 db=DBManager(str(tmp_path/"netguard.db"));session=db.create_session("Ethernet")
 alert=Alert(
  None,session,datetime.now(),"PORT_SCAN","HIGH","10.0.0.5","10.0.0.10",
  "Scan detected",1,False,rule_id="NG-PORT-SCAN",protocol="TCP",
  source_port=51000,destination_port=443,evidence='{"ports": [22, 80, 443]}',
  recommendation="Review and block the source if unauthorized.",
  cooldown_seconds=30,direction="inbound",interface_id=r"\Device\NPF_{TEST}",
 )
 db.insert_alert(alert);stored=db.get_alerts(session)[0]
 assert stored.rule_id=="NG-PORT-SCAN" and stored.protocol=="TCP"
 assert stored.source_port==51000 and stored.destination_port==443
 assert stored.evidence=={"ports":[22,80,443]}
 assert stored.recommendation.startswith("Review")
 assert stored.cooldown_seconds==30 and stored.last_seen is not None
 assert stored.direction=="inbound" and stored.interface_id==r"\Device\NPF_{TEST}"
 db.close()


def test_score_statistics_and_settings_persistence(tmp_path):
 db=DBManager(str(tmp_path/"netguard.db"));session=db.create_session("Ethernet")
 db.insert_packet_batch([rich_packet()],session)
 db.record_security_score(session,87,reason="test score")
 db.record_statistics_snapshot(session)
 db.set_setting("retention_enabled","false")

 score=db.get_security_score_history(session)[0]
 snapshot=db.get_statistics_snapshots(session)[0]
 assert score.score==87 and score.reason=="test score"
 assert snapshot.total_packets==1 and snapshot.total_bytes==120
 assert snapshot.outbound_packets==1 and snapshot.protocol_counts=={"HTTPS":1}
 assert db.get_setting("retention_enabled")=="false"
 db.close()


def test_clear_runtime_data_preserves_schema_and_settings(tmp_path):
 db=DBManager(str(tmp_path/"netguard.db"));session=db.create_session("Ethernet")
 db.insert_packet_batch([rich_packet()],session)
 db.insert_alert(Alert(None,session,datetime.now(),"TEST","LOW","a","b","test",1,False))
 db.record_security_score(session,90);db.record_statistics_snapshot(session)
 db.set_setting("browser_preference","kept")

 db.clear_runtime_data()

 summary=db.database_summary()
 assert all(count==0 for count in summary["row_counts"].values())
 assert db.schema_version==8
 assert db.get_setting("browser_preference")=="kept"
 db.close()


def test_retention_removes_old_history_but_protects_active_session(tmp_path):
 db=DBManager(str(tmp_path/"netguard.db"))
 inactive=db.create_session("old");active=db.create_session("active")
 now=datetime(2026,7,27,12);old=now-timedelta(days=60)

 for session in (inactive,active):
  db.insert_packet_batch([rich_packet(old)],session)
  db.insert_alert(Alert(None,session,old,"TEST","LOW","a","b","old",1,False,last_seen=old))
  db.record_security_score(session,90,timestamp=old)
  db.record_statistics_snapshot(session,timestamp=old)
 db.end_session(inactive,1,1,90)

 deleted=db.apply_retention(
  packet_days=30,connection_days=30,statistics_days=30,score_days=30,
  alert_days=30,active_session_id=active,reference_time=now,
 )

 assert all(count==1 for count in deleted.values())
 assert db.get_packets(inactive)==[] and db.get_connections(inactive)==[]
 assert db.get_security_score_history(inactive)==[]
 assert db.get_statistics_snapshots(inactive)==[] and db.get_alerts(inactive)==[]
 assert len(db.get_packets(active))==1 and len(db.get_connections(active))==1
 assert len(db.get_security_score_history(active))==1
 assert len(db.get_statistics_snapshots(active))==1 and len(db.get_alerts(active))==1
 db.close()
