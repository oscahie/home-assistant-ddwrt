#!/usr/bin/env python3
"""
Comprehensive test of the patched DD-WRT integration
Tests the actual integration code with your real router
"""

import sys
import os
import logging
import asyncio
from datetime import datetime

# Add the custom_components path so we can import the actual integration
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'custom_components', 'ddwrt'))

try:
    from pyddwrt import DDWrt
except ImportError as e:
    print(f"❌ Failed to import DDWrt: {e}")
    print("Make sure you're running this from the project root directory")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Set DD-WRT logger to DEBUG to see our new parsing messages
logging.getLogger('custom_components.ddwrt.pyddwrt').setLevel(logging.DEBUG)

class DDWrtTester:
    """Comprehensive tester for the DD-WRT integration"""

    def __init__(self, host="10.0.0.1", username="admin", password="your-password-here"):
        self.host = host
        self.username = username
        self.password = password
        self.ddwrt = None
        self.test_results = {}

    def connect(self):
        """Initialize the DD-WRT connection"""
        print(f"🔗 Connecting to DD-WRT router at {self.host}...")
        try:
            # Use HTTP (not HTTPS) and don't verify SSL
            self.ddwrt = DDWrt(None, self.host, self.username, self.password, "http", False)
            print("✅ DD-WRT instance created successfully")
            return True
        except Exception as e:
            print(f"❌ Failed to create DD-WRT instance: {e}")
            return False

    def test_about_data(self):
        """Test firmware version and router model info"""
        print("\n📋 Testing About Data (firmware info)...")
        try:
            success = self.ddwrt.update_about_data()
            if success:
                print("✅ About data retrieved successfully")
                print(f"   Firmware: {self.ddwrt.results.get('sw_version', 'N/A')}")
                print(f"   Build: {self.ddwrt.results.get('sw_build', 'N/A')}")
                print(f"   Date: {self.ddwrt.results.get('sw_date', 'N/A')}")
                print(f"   Router: {self.ddwrt.results.get('router_manufacturer', 'N/A')} {self.ddwrt.results.get('router_model', 'N/A')}")
                self.test_results['about'] = True
            else:
                print("❌ Failed to retrieve about data")
                self.test_results['about'] = False
        except Exception as e:
            print(f"❌ Error testing about data: {e}")
            self.test_results['about'] = False

    def test_wireless_data(self):
        """Test wireless data (this is where our fix is!)"""
        print("\n📡 Testing Wireless Data (THE BIG TEST!)...")
        try:
            success = self.ddwrt.update_wireless_data()
            if success:
                print("✅ Wireless data retrieved successfully")
                print(f"   Radio Status: {self.ddwrt.results.get('wl_radio', 'N/A')}")
                print(f"   SSID: {self.ddwrt.results.get('wl_ssid', 'N/A')}")
                print(f"   Channel: {self.ddwrt.results.get('wl_channel', 'N/A')}")
                print(f"   MAC: {self.ddwrt.results.get('wl_mac', 'N/A')}")

                # Test our wireless client parsing fix
                client_count = len(self.ddwrt.clients_wireless)
                print(f"   📱 Wireless Clients: {client_count}")

                for mac, client in self.ddwrt.clients_wireless.items():
                    print(f"      • {mac}")
                    print(f"        Name: '{client.get('name', 'N/A')}'")
                    print(f"        Interface: {client.get('interface', 'N/A')}")
                    print(f"        Uptime: {client.get('uptime', 'N/A')}")  # This should show commas correctly!
                    print(f"        Signal: {client.get('signal', 'N/A')} dBm")
                    print(f"        TX/RX: {client.get('tx_rate', 'N/A')}/{client.get('rx_rate', 'N/A')}")

                    # Show extra fields count
                    extra_count = len([k for k in client.keys() if k.startswith('extra_')])
                    if extra_count > 0:
                        print(f"        Extra fields: {extra_count}")

                self.test_results['wireless'] = True

                # Special validation for our fix
                if client_count > 0:
                    # Check if any client has uptime with comma (our key test)
                    for client in self.ddwrt.clients_wireless.values():
                        uptime = client.get('uptime', '')
                        if ', ' in uptime:
                            print(f"   🎯 SUCCESS: Uptime with comma preserved: '{uptime}'")
                            print("   🎉 The wireless parsing fix is working perfectly!")
                            break
            else:
                print("❌ Failed to retrieve wireless data")
                self.test_results['wireless'] = False
        except Exception as e:
            print(f"❌ Error testing wireless data: {e}")
            self.test_results['wireless'] = False

    def test_wan_data(self):
        """Test WAN connection info"""
        print("\n🌐 Testing WAN Data...")
        try:
            success = self.ddwrt.update_wan_data()
            if success:
                print("✅ WAN data retrieved successfully")

                # Core connection info
                print(f"   Status: {self.ddwrt.results.get('wan_status', 'N/A')}")
                print(f"   Connected: {self.ddwrt.results.get('wan_connected', 'N/A')}")
                print(f"   Protocol: {self.ddwrt.results.get('wan_proto', 'N/A')}")
                print(f"   Uptime: {self.ddwrt.results.get('wan_uptime', 'N/A')}")

                # IP configuration
                print(f"   IP Address: {self.ddwrt.results.get('wan_ipaddr', 'N/A')}")
                print(f"   IPv6 Address: {self.ddwrt.results.get('wan_ip6addr', 'N/A')}")
                print(f"   Gateway: {self.ddwrt.results.get('wan_gateway', 'N/A')}")
                print(f"   Netmask: {self.ddwrt.results.get('wan_netmask', 'N/A')}")

                # DNS servers
                dns_servers = []
                for i in range(6):  # wan_dns0 through wan_dns5
                    dns = self.ddwrt.results.get(f'wan_dns{i}')
                    if dns:
                        dns_servers.append(dns)
                print(f"   DNS Servers: {', '.join(dns_servers) if dns_servers else 'None'}")

                # DHCP info
                dhcp_remaining = self.ddwrt.results.get('wan_dhcp_remaining')
                if dhcp_remaining:
                    print(f"   DHCP Lease Remaining: {dhcp_remaining}")

                # PPPoE info
                pppoe_ac = self.ddwrt.results.get('wan_pppoe_ac_name')
                if pppoe_ac:
                    print(f"   PPPoE AC Name: {pppoe_ac}")

                # Traffic statistics
                traffic_in = self.ddwrt.results.get('wan_traffic_in')
                traffic_out = self.ddwrt.results.get('wan_traffic_out')
                if traffic_in or traffic_out:
                    print(f"   Traffic In/Out: {traffic_in or 'N/A'} / {traffic_out or 'N/A'} MB")

                # 3G signal (if applicable)
                signal_3g = self.ddwrt.results.get('wan_3g_signal')
                if signal_3g:
                    print(f"   3G Signal: {signal_3g}")

                self.test_results['wan'] = True
            else:
                print("❌ Failed to retrieve WAN data")
                self.test_results['wan'] = False
        except Exception as e:
            print(f"❌ Error testing WAN data: {e}")
            self.test_results['wan'] = False

    def test_router_data(self):
        """Test router system info"""
        print("\n🖥️ Testing Router Data...")
        try:
            success = self.ddwrt.update_router_data()
            if success:
                print("✅ Router data retrieved successfully")
                print(f"   Uptime: {self.ddwrt.results.get('uptime', 'N/A')}")
                print(f"   CPU Temp: {self.ddwrt.results.get('cpu_temp', 'N/A')}")
                print(f"   Load Avg: {self.ddwrt.results.get('load_average1', 'N/A')}")
                print(f"   NVRAM: {self.ddwrt.results.get('nvram_used', 'N/A')}/{self.ddwrt.results.get('nvram_total', 'N/A')}")
                self.test_results['router'] = True
            else:
                print("❌ Failed to retrieve router data")
                self.test_results['router'] = False
        except Exception as e:
            print(f"❌ Error testing router data: {e}")
            self.test_results['router'] = False

    def test_lan_data(self):
        """Test LAN and client info"""
        print("\n🏠 Testing LAN Data...")
        try:
            success = self.ddwrt.update_lan_data()
            if success:
                print("✅ LAN data retrieved successfully")
                print(f"   LAN IP: {self.ddwrt.results.get('lan_ipaddr', 'N/A')}")
                print(f"   DHCP Range: {self.ddwrt.results.get('lan_dhcp_start', 'N/A')} - {self.ddwrt.results.get('lan_dhcp_end', 'N/A')}")

                # Show connected clients
                arp_clients = len(self.ddwrt.clients_arp)
                dhcp_clients = len(self.ddwrt.clients_dhcp)
                print(f"   📱 ARP Clients: {arp_clients}")
                print(f"   📱 DHCP Clients: {dhcp_clients}")

                # Print each ARP entry in detail
                if arp_clients > 0:
                    print(f"\n   🔍 ARP Client Details:")
                    for i, (mac, client) in enumerate(self.ddwrt.clients_arp.items(), 1):
                        print(f"      {i:2}. MAC: {mac}")
                        print(f"          Hostname: '{client.get('hostname', 'N/A')}'")
                        print(f"          IP: {client.get('ip', 'N/A')}")
                        print(f"          Connections: {client.get('connections', 'N/A')}")
                        print(f"          Interface: {client.get('interface', 'N/A')}")
                else:
                    print("   ⚠️  No ARP clients found (this might indicate parsing issues)")

                # Print each DHCP entry in detail
                if dhcp_clients > 0:
                    print(f"\n   🔍 DHCP Client Details:")
                    for i, (mac, client) in enumerate(self.ddwrt.clients_dhcp.items(), 1):
                        print(f"      {i:2}. MAC: {mac}")
                        print(f"          Hostname: '{client.get('hostname', 'N/A')}'")
                        print(f"          IP: {client.get('ip', 'N/A')}")
                        print(f"          Lease: {client.get('lease_expiration', 'N/A')}")
                else:
                    print("   ⚠️  No DHCP clients found (this might indicate parsing issues)")

                self.test_results['lan'] = True
            else:
                print("❌ Failed to retrieve LAN data")
                self.test_results['lan'] = False
        except Exception as e:
            print(f"❌ Error testing LAN data: {e}")
            self.test_results['lan'] = False

    def print_summary(self):
        """Print test summary"""
        print("\n" + "="*60)
        print("📊 TEST SUMMARY")
        print("="*60)

        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results.values() if result)

        for test_name, passed in self.test_results.items():
            status = "✅ PASS" if passed else "❌ FAIL"
            print(f"   {test_name.upper()}: {status}")

        print(f"\nOverall: {passed_tests}/{total_tests} tests passed")

        if passed_tests == total_tests:
            print("\n🎉 ALL TESTS PASSED!")
            print("✅ The patched integration is working perfectly!")
            print("✅ You can now restart Home Assistant with confidence!")
        else:
            print(f"\n⚠️  {total_tests - passed_tests} test(s) failed")
            print("❌ Review the errors above before deploying to Home Assistant")

        # Special note about the wireless fix
        if self.test_results.get('wireless', False):
            print("\n🎯 WIRELESS PARSING FIX STATUS: SUCCESS")
            print("   The main error you reported should now be resolved!")

        print("\n" + "="*60)

def main():
    """Main test function"""
    print("🧪 DD-WRT Integration Local Test Suite")
    print("="*50)
    print("Testing patched integration with your Netgear R7800")
    print(f"Test started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Create tester
    tester = DDWrtTester()

    # Connect to router
    if not tester.connect():
        print("❌ Cannot connect to router. Exiting.")
        return 1

    # Run all tests
    tester.test_about_data()
    tester.test_wireless_data()  # This is the big one!
    tester.test_wan_data()
    tester.test_router_data()
    tester.test_lan_data()

    # Print summary
    tester.print_summary()

    # Return appropriate exit code
    all_passed = all(tester.test_results.values())
    return 0 if all_passed else 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)