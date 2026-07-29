"""Tests for thread-safe rolling statistics."""
from datetime import datetime,timedelta
from core.models import Packet
from core.stats_tracker import StatsTracker
def packet(timestamp,protocol="TCP",dst_port=443):
 return Packet(timestamp,"10.0.0.10","10.0.0.20",50000,dst_port,protocol,100,"outbound")
def test_record_packet_and_window_expiry():
 now=datetime.now();tracker=StatsTracker(window_seconds=10);tracker.record_packet(packet(now));tracker.record_packet(packet(now,protocol="UDP",dst_port=53))
 assert tracker.get_protocol_distribution()=={"TCP":1,"UDP":1};assert len(tracker.get_active_connections())==2;assert tracker.get_packet_rate()==.2
 tracker.record_packet(packet(now+timedelta(seconds=11)))
 assert tracker.get_protocol_distribution()=={"TCP":1};assert len(tracker.get_active_connections())==1
def test_reset_clears_live_state():
 tracker=StatsTracker();tracker.record_packet(packet(datetime.now()));tracker.reset();assert tracker.get_protocol_distribution()=={};assert tracker.get_bandwidth_history()==[];assert tracker.get_active_connections()==[]
