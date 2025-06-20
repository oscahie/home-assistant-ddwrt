"""Class for querying DD-WRT routers"""

from datetime import date
import logging
import re
import ssl
import urllib3
from OpenSSL import crypto
from datetime import datetime
from requests import Session
from requests.exceptions import Timeout, ConnectionError, SSLError
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

_LOGGER = logging.getLogger(__name__)
_VERSION = "0.9.4"
_X_REQUESTED_WITH = __name__ + "-" + _VERSION
HTTP_X_REQUESTED_WITH = "X-Requested-With"

CONF_TRACK_ARP = "arp_clients"
CONF_TRACK_DHCP = "dhcp_clients"
CONF_TRACK_PPPOE = "pppoe_clients"
CONF_TRACK_PPTP = "pptp_clients"
CONF_TRACK_WDS = "wds_clients"
CONF_TRACK_WIRELESS = "wireless_clients"

DEFAULT_TIMEOUT = 4

ENDPOINT_ABOUT = "About.htm"
ENDPOINT_APPLY = "apply.cgi"
ENDPOINT_AOSS = "AOSS.live.asp"
ENDPOINT_CONNTRACK = "Status_Conntrack.asp"
ENDPOINT_DDNS = "DDNS.live.asp"
ENDPOINT_FREERADIUS = "FreeRadius.live.asp"
ENDPOINT_TTGRAPH = "ttgraph.cgi"
ENDPOINT_INTERNET = "Status_Internet.live.asp"
ENDPOINT_NETWORKING = "Networking.live.asp"
ENDPOINT_STATUSINFO = "Statusinfo.live.asp"
ENDPOINT_LAN = "Status_Lan.live.asp"
ENDPOINT_ROUTER_STATIC = "Status_Router.asp"
ENDPOINT_ROUTER = "Status_Router.live.asp"
ENDPOINT_SPUTNIK = "Status_SputnikAPD.live.asp"
ENDPOINT_WIRELESS = "Status_Wireless.live.asp"
ENDPOINT_UPNP = "UPnP.live.asp"
ENDPOINT_USB = "USB.live.asp"
REBOOT_PARAMETERS = {
    'submit_button': 'Management',
    'action': 'Reboot',
    'change_action': '',
    'submit_type': '',
}
RUN_COMMAND_PARAMETERS = {
    'submit_button': 'Ping',
    'action': 'ApplyTake',
    'submit_type': 'start',
    'change_action': 'gozila_cgi',
    'ping_ip': '',
}
UPNP_DELETE_PARAMETERS = {
    'submit_button': 'UPnP',
    'action': 'Apply',
    'change_action': '',
    'submit_type': '',
    'remove': '',
}
WOL_PARAMETERS = {
    'submit_button': 'Ping',
    'action': 'Apply',
    'submit_type': 'wol',
    'change_action': 'gozila_cgi',
    'manual_wol_mac': '',
    'manual_wol_network': '',
    'manual_wol_port': '',
}
WAN_RELEASE_PARAMETERS = {
    'submit_button': 'Status_Internet',
    'action': 'Apply',
    'change_action': 'gozila_cgi',
    'submit_type': 'release',
}
WAN_RENEW_PARAMETERS = {
    'submit_button': 'Status_Internet',
    'action': 'Apply',
    'change_action': 'gozila_cgi',
    'submit_type': 'renew',
}
WAN_CONNECT_PPPOE_PARAMETERS = {
    'submit_button': 'Status_Internet',
    'action': 'Apply',
    'change_action': 'gozila_cgi',
    'submit_type': 'Connect_pppoe',
}
WAN_DISCONNECT_PPPOE_PARAMETERS = {
    'submit_button': 'Status_Internet',
    'action': 'Apply',
    'change_action': 'gozila_cgi',
    'submit_type': 'Disconnect_pppoe',
}
WIFI_SELECT_INTERFACE_PARAMETERS = {
    'submit_button': 'Status_Wireless',
#    'next_page': 'Status_Wireless.asp',
    'change_action': 'gozila_cgi',
    'submit_type': 'refresh',
    'wifi_display': 'wl0',
}

_DDWRT_DATA_REGEX = re.compile(r"\{(\w+)::([^\}]*)\}")


class DDWrt:
    """This class queries a wireless router running DD-WRT firmware."""

    def __init__(self, aio_session, host, username, password, protocol, verify_ssl):
        """Initialize the DD-WRT class."""

        self._aio_session = aio_session
        self._host = host
        self._username = username
        self._password = password
        self._protocol = protocol
        self._verify_ssl = verify_ssl

        self.data = None
        self.results = {}
        self.clients_arp = {}
        self.clients_dhcp = {}
        self.clients_pppoe = {}
        self.clients_pptp = {}
        self.clients_wds = {}
        self.clients_wireless = {}
        self.upnp_forwards = {}

        # Configure session with retries
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.3,
            status_forcelist=[500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self._session = Session()
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)


    def update_about_data(self):
        """Gets firmware version info from the DD-WRT router"""

        _LOGGER.debug("DDWrt.update_about_data: Updating about data...")

        url = f"{self._protocol}://{self._host}/{ENDPOINT_ABOUT}"

        try:
            self.data = self._get_ddwrt_data(url, False)
        except Exception as e:
#            pass
            raise(DDWrt.DDWrtException("Unable to update about data: %s", e))
            return None

        if not self.data:
            return False

        # Get firmware info
        firmware = self.data.partition("DD-WRT v")[2].split("<br />")[0]
        self.results.update({"sw_version": firmware.split("-r")[0]})
        self.results.update({"sw_build": firmware.split("-r")[1].split(" ")[0]})
        self.results.update({"sw_date": firmware.split("(")[1].split(")")[0]})

        url = f"{self._protocol}://{self._host}/{ENDPOINT_ROUTER_STATIC}"

        try:
            self.data = self._get_ddwrt_data(url, False)
        except Exception as e:
#            pass
            raise(DDWrt.DDWrtException("Unable to update router model data: %s", e))
            return None

        if not self.data:
            return False

        # Get router model
        router_model = self.data.partition("Capture(status_router.sys_model)</script></div>")[2].split("</div>")[0].split(" ", 1)
        self.results.update({"router_manufacturer": router_model[0]})
        self.results.update({"router_model": router_model[1]})

        _LOGGER.debug("DDWrt::update_about_data results=%s", self.results)

        return True


    def update_wan_data(self):
        """Gets WAN info from the DD-WRT router"""

        _LOGGER.debug("DDWrt.update_wan_data: Updating WAN data...")

        # Get data from internet endpoint
        url = f"{self._protocol}://{self._host}/{ENDPOINT_INTERNET}"
        try:
            self.data = self._get_ddwrt_data(url, True)
        except Exception as e:
            raise(DDWrt.DDWrtException("Unable to update WAN data: %s", e))
            return None

        if not self.data:
            return False

        # Get WAN info
        self.results.update({"wan_3g_signal": self.data.pop("wan_3g_signal").split(" ")[0]})
        if self.results["wan_3g_signal"].lower() == "n.a.":
            self.results.update({"wan_3g_signal": None})
        self._get_parameter("wan_dhcp_remaining", "dhcp_remaining")
        self._get_parameter("wan_dns0", "wan_dns0")
        self._get_parameter("wan_dns1", "wan_dns1")
        self._get_parameter("wan_dns2", "wan_dns2")
        self._get_parameter("wan_dns3", "wan_dns3")
        self._get_parameter("wan_dns4", "wan_dns4")
        self._get_parameter("wan_dns5", "wan_dns5")
        self._get_parameter("wan_gateway", "wan_gateway")
        self._get_parameter("wan_ipaddr", "wan_ipaddr")
        if "wan_ipv6addr" in self.data:
            self.results.update({"wan_ip6addr": self.data.pop("wan_ipv6addr")})
            if "ipinfo" in self.data:
                del self.data["ipinfo"]
        else:
            if "ipinfo" in self.data and "IPv6" in self.data.get("ipinfo", ""):
                self.results.update({"wan_ip6addr": self.data.pop("ipinfo").split("IPv6:")[1].strip()})
            else:
                if "ipinfo" in self.data:
                    del self.data["ipinfo"]
                self.results.update({"wan_ip6addr": None})
        self._get_parameter("wan_netmask", "wan_netmask")
        self._get_parameter("wan_pppoe_ac_name", "pppoe_ac_name")
        self._get_parameter("wan_proto", "wan_shortproto")
        self._get_parameter("wan_traffic_in", "ttraff_in")
        self._get_parameter("wan_traffic_out", "ttraff_out")

        # Parse WAN status with improved HTML handling
        wan_status_raw = self.data.pop("wan_status").strip()
        # Remove HTML tags and get the first meaningful word
        if "<" in wan_status_raw:
            # Extract status before any HTML tags
            wan_status_text = wan_status_raw.split("<")[0].strip()
        else:
            wan_status_text = wan_status_raw.split("&nbsp;")[0].strip()

        # Clean up HTML entities
        wan_status_text = wan_status_text.replace("&nbsp;", " ").replace("&amp;", "&").strip()

        # Determine connection status more intelligently
        # Check if we have a valid WAN IP address (not just rely on status text)
        wan_ip = self.results.get("wan_ipaddr", "")
        has_valid_ip = wan_ip and "/" in wan_ip and not wan_ip.startswith("0.0.0.0")

        if has_valid_ip:
            # If we have a valid IP, we're probably connected despite what status says
            self.results.update({"wan_connected": True})
            if wan_status_text.lower() in ["error", "disconnected", "connecting"]:
                _LOGGER.debug("WAN status shows '%s' but we have valid IP %s - correcting to 'Connected'",
                            wan_status_text, wan_ip)
                # Correct the status to reflect reality
                self.results.update({"wan_status": "Connected"})
            else:
                self.results.update({"wan_status": wan_status_text})
        else:
            # No valid IP, use the status text as-is
            self.results.update({"wan_status": wan_status_text})
            self.results.update({"wan_connected": wan_status_text.lower() == "connected"})

        self.results.update({"wan_uptime": self.data.pop("wan_uptime").strip().split(",  ")[0]})

        # Clean up known standard fields that appear in all endpoints
        if "uptime" in self.data:
            del self.data["uptime"]

        # Handle known speed test fields (these can be ignored for WAN status)
        known_speed_fields = {
            'speed_up', 'speed_down', 'speed_town',
            'speed_sponsor', 'speed_country', 'speed_latency'
        }
        for field in known_speed_fields:
            if field in self.data:
                del self.data[field]

        # Report any remaining unhandled fields
        if self.data:
            _LOGGER.warning("Unhandled WAN data fields found: %s", self.data)

        return True


    def update_router_data(self):
        """Gets router info from the DD-WRT router"""

        _LOGGER.debug("DDWrt.update_router_data: Updating router data...")

        # Get data from router endpoint
        url = f"{self._protocol}://{self._host}/{ENDPOINT_ROUTER}"
        try:
            self.data = self._get_ddwrt_data(url, True)
        except Exception as e:
            raise(DDWrt.DDWrtException("Unable to update router data: %s", e))
            return None

        if not self.data:
            return False

        try:
            # Handle CPU temperature data
            cpu_temp_data = self.data.pop("cpu_temp", None)
            if cpu_temp_data and isinstance(cpu_temp_data, str):
                temp_str = cpu_temp_data.strip()
                if temp_str and temp_str != "Not available":
                    # Parse HTML-encoded temperature data
                    # Example: "CPU 48.829 &#176;C / wlan1 56 &#176;C"
                    cpu_temp = {}
                    for item in temp_str.split("/"):
                        parts = item.strip().split()
                        if len(parts) >= 2:
                            try:
                                # Extract temperature value, removing HTML entities
                                temp_value = parts[1].replace("&#176;C", "").replace("°C", "")
                                cpu_temp[parts[0].strip()] = float(temp_value)
                            except (ValueError, IndexError):
                                _LOGGER.warning("Invalid CPU temperature format: %s", item)
                    self.results["cpu_temp"] = cpu_temp if cpu_temp else None
                else:
                    self.results["cpu_temp"] = None
            else:
                self.results["cpu_temp"] = None

            # Handle individual CPU temperature fields (alternative format)
            cpu_temps = {}
            for i in range(3):
                temp_key = f'cpu_temp{i}'
                if temp_key in self.data:
                    temp_str = self.data.pop(temp_key).split('&#176;')[0].strip()
                    try:
                        cpu_temps[f'CPU{i}'] = float(temp_str)
                    except (ValueError, TypeError):
                        _LOGGER.warning("Invalid CPU temperature format: %s", temp_str)

            # Use individual temps if main cpu_temp wasn't available
            if not self.results.get("cpu_temp") and cpu_temps:
                self.results["cpu_temp"] = cpu_temps

            # Handle router time
            if 'router_time' in self.data:
                self.results['router_time'] = self.data.pop('router_time')

            # Handle IP connection tracking
            if 'ip_conntrack' in self.data:
                self.results['ip_connections'] = self.data.pop('ip_conntrack')

            # Handle clock frequency
            if 'clkfreq' in self.data:
                self.results['clk_freq'] = self.data.pop('clkfreq')

            # Handle voltage
            if 'voltage' in self.data:
                voltage = self.data.pop('voltage')
                self.results['voltage'] = float(voltage) if voltage and voltage.strip() else None

            # Handle uptime and load averages
            if 'uptime' in self.data:
                uptime_str = self.data.pop('uptime')
                if 'up ' in uptime_str:
                    # Extract uptime portion
                    uptime_part = uptime_str.split('up ')[1].split(',')[0].strip()
                    self.results['uptime'] = uptime_part

                    # Extract load averages
                    if 'load average:' in uptime_str:
                        load_str = uptime_str.split('load average:')[1].strip()
                        load_avgs = [avg.strip() for avg in load_str.split(',')]
                        if len(load_avgs) >= 3:
                            self.results['load_average1'] = load_avgs[0]
                            self.results['load_average5'] = load_avgs[1]
                            self.results['load_average15'] = load_avgs[2]

            # Handle NVRAM usage
            if 'nvram' in self.data:
                nvram_str = self.data.pop('nvram')
                if '/' in nvram_str:
                    try:
                        used, total = nvram_str.split('/')
                        self.results['nvram_used'] = used.strip().split()[0]
                        self.results['nvram_total'] = total.strip().split()[0]
                    except (ValueError, IndexError):
                        _LOGGER.warning("Invalid NVRAM format: %s", nvram_str)

            # Handle wireless radio status
            if 'wl_radio' in self.data:
                wl_radio = self.data.pop("wl_radio").strip().split(" ")
                try:
                    self.results["wl_radio"] = any(
                        status.lower() in ["on", "aktiverad", "enabled", "active", "1", "true"]
                        for status in wl_radio
                    )
                except Exception as e:
                    _LOGGER.error("Unknown wireless radio status format: %s", wl_radio)
                    self.results["wl_radio"] = None

            # Clean up standard fields that appear in multiple endpoints
            if 'ipinfo' in self.data:
                del self.data['ipinfo']

            # Handle memory info (large data, just remove for now)
            if 'mem_info' in self.data:
                del self.data['mem_info']

            # Report any remaining unhandled fields
            if self.data:
                _LOGGER.warning("Extra fields in router data found. Please contact developer to report this warning. (%s)", self.data)

            return True

        except Exception as e:
            _LOGGER.error("Error processing router data: %s", e)
            return False


    def update_network_data(self):
        """Gets Networking info from the DD-WRT router"""

        _LOGGER.debug("DDWrt.update_network_data: Updating Networking data...")

        # Get data from networking endpoint
        url = f"{self._protocol}://{self._host}/{ENDPOINT_NETWORKING}"
        try:
            self.data = self._get_ddwrt_data(url, True)
        except Exception as e:
            raise(DDWrt.DDWrtException("Unable to update networking data: %s", e))
            return None

        if not self.data:
            return False

        # Get Networking info
        network_bridges = [item.strip("'").strip() for item in self.data.pop("bridges_table").split(",")]

        self.results.update({"network_bridges": network_bridges})

        del self.data["uptime"]
        del self.data["ipinfo"]
        if self.data:
            _LOGGER.warning("Extra fields in networking data found. Please contact developer to report this warning. (%s)", self.data)

        return True


    def update_wireless_data(self):
        """Gets wireless info from the DD-WRT router"""

        _LOGGER.debug("DDWrt.update_wireless_data: Updating wireless data...")

        url = f"{self._protocol}://{self._host}/{ENDPOINT_WIRELESS}"
        try:
            self.data = self._get_ddwrt_data(url, True)
        except Exception as e:
            raise(DDWrt.DDWrtException("Unable to update wireless data: %s", e))
            return None

        if not self.data:
            return False

        # Get wireless info
        wl_ack = self.data.pop("wl_ack")
        if wl_ack and not wl_ack == "" and not wl_ack == "N/A":
            self.results.update({"wl_ack_timing": wl_ack.split("&#181;")[0]})
            self.results.update({"wl_ack_distance": wl_ack.split("(")[1].split("m")[0]})
        else:
            self.results.update({"wl_ack_timing": None})
            self.results.update({"wl_ack_distance": None})
        self._get_parameter("wl_active", "wl_active")
        self._get_parameter("wl_busy", "wl_busy")
        self._get_parameter("wl_channel", "wl_channel")
        self._get_parameter("wl_count", "assoc_count")
        self._get_parameter("wl_mac", "wl_mac")
        self._get_parameter("wl_quality", "wl_quality")
        wl_radio = self.data.pop("wl_radio").strip().split(" ")
        try:
            self.results.update({"wl_radio": any(
                status.lower() in ["on", "aktiverad", "enabled", "active", "1", "true"]
                for status in wl_radio
            )})
        except Exception as e:
            _LOGGER.error("Unknown wireless radio status, please report this to the author: %s", wl_radio)
            self.results.update({"wl_radio": None})
        self.results.update({"wl_rate": self.data.pop("wl_rate").split(" ")[0]})
        self._get_parameter("wl_ssid", "wl_ssid")
        self.results.update({"wl_xmit": self.data.pop("wl_xmit").split(" ")[0]})
        if self.results["wl_xmit"] == "Radio":
            self.results.update({"wl_xmit": None})

        # Get wireless packet info
        packet_info = self.data.pop("packet_info")

        if packet_info:
            elements = dict((key.strip(), value.strip()) for key, value in (item.split('=') for item in packet_info.strip(';').split(';')))

            wl_rx_packet_error = elements.get("SWRXerrorPacket", None)
            wl_rx_packet_ok = elements.get("SWRXgoodPacket", None)
            wl_tx_packet_error = elements.get("SWTXerrorPacket", None)
            wl_tx_packet_ok = elements.get("SWTXgoodPacket", None)

            self.results.update({"wl_rx_packet_error": wl_rx_packet_error})
            self.results.update({"wl_rx_packet_ok": wl_rx_packet_ok})
            self.results.update({"wl_tx_packet_error": wl_tx_packet_error})
            self.results.update({"wl_tx_packet_ok": wl_tx_packet_ok})
        else:
            self.results.update({"wl_rx_packet_error": None})
            self.results.update({"wl_rx_packet_ok": None})
            self.results.update({"wl_tx_packet_error": None})
            self.results.update({"wl_tx_packet_ok": None})


        # Get wireless clients
        active_clients = self.data.pop("active_wireless", None)

        if active_clients:
            self.clients_wireless = self._parse_wireless_clients_robust(active_clients)

        _LOGGER.debug("DDWrt.update_wireless_data: Wireless clients: %s", self.clients_wireless)

        # Get WDS clients
        active_clients = self.data.pop("active_wds", None)

        if active_clients:
            self.clients_wds = {}
            elements = [item.strip().strip("'") for item in active_clients.strip().split(",")]
            if (len(elements) != 0) and ((len(elements) % 7) == 0):
                # WDS elements: MAC Address | Interface | Description | Signal | Noise | SNR | Signal Quality
                for i in range(0, len(elements), 7):
                    _LOGGER.info("interface=%s", elements[i+4])
                    self.clients_wds.update( {
                        elements[i]: {
                            "name": elements[i + 2],
                            "type": CONF_TRACK_WDS,
                            "interface": elements[i + 1],
                            "description": elements[i + 2],
                            "signal": elements[i + 3],
                            "noise": elements[i + 4],
                            "snr": elements[i + 5],
                            "signal_quality": elements[i + 6],
                        }
                    }
                )
            else:
                _LOGGER.warning("update_wireless_data(): invalid number of elements in active_wds (expected 7, found %i)", len(elements))

        _LOGGER.debug("DDWrt.update_wireless_data: WDS clients: %s", self.clients_wds)

        del self.data["uptime"]
        del self.data["ipinfo"]
        if self.data:
            _LOGGER.warning("Extra fields in wireless data found. Please contact developer to report this warning. (%s)", self.data)

        try:
            # Handle wireless radio status robustly
            wl_radio = self.data.get("wl_radio", "").strip()
            self.results["wl_radio"] = any(
                status.lower() in ["on", "enabled", "aktiverad", "active", "1", "true"]
                for status in wl_radio.split()
            )

            # ...rest of wireless data processing...

        except Exception as e:
            _LOGGER.error("Error processing wireless data: %s", e)
            return False

        return True


    def update_lan_data(self):
        """Gets LAN info from the DD-WRT router"""

        _LOGGER.debug("DDWrt.update_lan_data: Updating LAN data...")

        url = f"{self._protocol}://{self._host}/{ENDPOINT_LAN}"
        try:
            self.data = self._get_ddwrt_data(url, True)
        except Exception as e:
            raise(DDWrt.DDWrtException("Unable to update LAN data: %s", e))
            return None

        if not self.data:
            return False

        # Get LAN info
        if "lan_ip_prefix" in self.data:
            dhcp_prefix = self.data.pop("lan_ip_prefix")
            dhcp_start = self.data.pop("dhcp_start")
            lan_dhcp_start = "{}{}".format(dhcp_prefix, dhcp_start)
            lan_dhcp_end = "{}{}".format(dhcp_prefix, int(dhcp_start)+int(self.data.pop("dhcp_num"))-1)
        else:
            lan_dhcp_start = self.data.pop("dhcp_start")
            lan_dhcp_end = self.data.pop("dhcp_end")
            del self.data["dhcp_num"]
        self.results.update({"lan_dhcp_start": lan_dhcp_start})
        self.results.update({"lan_dhcp_end": lan_dhcp_end})

        self._get_parameter("lan_dhcp_daemon", "dhcp_daemon")
        self._get_parameter("lan_dhcp_lease_time", "dhcp_lease_time")

        self._get_parameter("lan_dns", "lan_dns")
        self._get_parameter("lan_gateway", "lan_gateway")
        self._get_parameter("lan_ipaddr", "lan_ip")
        self._get_parameter("lan_mac", "lan_mac")
        self._get_parameter("lan_netmask", "lan_netmask")
        self._get_parameter("lan_proto", "lan_proto")

        # Get clients from ARP table
        active_clients = self.data.pop("arp_table", None)
        if active_clients:
            self.clients_arp = self._parse_arp_table_robust(active_clients)
        else:
            self.clients_arp = {}

        _LOGGER.debug("DDWrt.update_lan_data: ARP clients: %s", self.clients_arp)

        # Get clients from DHCP leases
        active_clients = self.data.pop("dhcp_leases", None)
        if active_clients:
            self.clients_dhcp = self._parse_dhcp_leases_robust(active_clients)
        else:
            self.clients_dhcp = {}

        _LOGGER.debug("DDWrt.update_lan_data: DHCP clients: %s", self.clients_dhcp)

        # Get clients from PPPoE leases
        active_clients = self.data.pop("pppoe_leases", None)
        if active_clients:
            self.clients_pppoe = self._parse_pppoe_leases_robust(active_clients)
        else:
            self.clients_pppoe = {}

        _LOGGER.debug("DDWrt.update_lan_data: PPPoE clients: %s", self.clients_pppoe)

        # Get clients from PPTP leases
        active_clients = self.data.pop("pptp_leases", None)
        if active_clients:
            self.clients_pptp = self._parse_pptp_leases_robust(active_clients)
        else:
            self.clients_pptp = {}

        _LOGGER.debug("DDWrt.update_lan_data: PPTP clients: %s", self.clients_pptp)

        del self.data["uptime"]
        del self.data["ipinfo"]
        if self.data:
            _LOGGER.warning("Extra fields in LAN data found. Please contact developer to report this warning. (%s)", self.data)

        return True


    def update_upnp_data(self):
        """Gets UPNP info from the DD-WRT router"""

        _LOGGER.debug("DDWrt.update_upnp_data: Updating UPNP data...")

        url = f"{self._protocol}://{self._host}/{ENDPOINT_UPNP}"
        try:
            self.data = self._get_ddwrt_data(url, True)
        except Exception as e:
            raise(DDWrt.DDWrtException("Unable to update UPNP data: %s", e))
            return None

        if not self.data:
            return False

        # Get UPNP forwards
        upnp_data = self.data.pop("upnp_forwards", None)

        try:
            if upnp_data:
                self.upnp_forwards = {}
                elements = [item.strip().strip("'") for item in upnp_data.strip().split(",") if item.strip()]

                if not elements:
                    return True

                # Group elements into chunks of 4
                element_groups = [elements[i:i+4] for i in range(0, len(elements), 4)]

                for group in element_groups:
                    if len(group) == 4:  # Only process complete groups
                        # Process UPNP forward entry
                        name = group[3]  # Last element is name
                        upnp_parts = group[0].split('>')[0].split('-')
                        if len(upnp_parts) >= 2:
                            self.upnp_forwards[name] = {
                                'wan_port_start': upnp_parts[0],
                                'wan_port_end': upnp_parts[1],
                                'protocol': group[1],
                                'enabled': group[2]
                            }

        except Exception as e:
            _LOGGER.error("Error processing UPNP data: %s", e)
            return False

        _LOGGER.debug("DDWrt.update_upnp_data: UPNP forwards: %s", self.upnp_forwards)

        del self.data["uptime"]
        del self.data["ipinfo"]
        if self.data:
            _LOGGER.warning("Extra fields in UPNP data found. Please contact developer to report this warning. (%s)", self.data)

        return True


    def wan_dhcp_release(self):
        """Releases the DHCP lease from the WAN interface."""

        url = f"{self._protocol}://{self._host}/{ENDPOINT_APPLY}"

        try:
            self.data = self._post_ddwrt_data(url, WAN_RELEASE_PARAMETERS)
        except Exception as e:
            _LOGGER.debug("DDWrt.wan_dhcp_release: Unable to send WAN DHCP release command.")
            raise(DDWrt.DDWrtException("Unable to send WAN DHCP release command: %s", e))

        if not self.data:
            _LOGGER.debug("DDWrt.wan_dhcp_release: Unable to release DHCP lease from WAN interface (no data returned).")
            raise(DDWrt.DDWrtException("Unable to release DHCP lease from WAN interface (no data returned)"))

        _LOGGER.debug("DDWrt.wan_dhcp_release: succes.")
        return True


    def wan_dhcp_renew(self):
        """Renews the DHCP lease for the WAN interface."""

        url = f"{self._protocol}://{self._host}/{ENDPOINT_APPLY}"

        try:
            self.data = self._post_ddwrt_data(url, WAN_RENEW_PARAMETERS)
        except Exception as e:
            _LOGGER.debug("DDWrt.wan_dhcp_renew: Unable to send WAN DHCP renew command.")
            raise(DDWrt.DDWrtException("Unable to send WAN DHCP renew command: %s", e))

        if not self.data:
            _LOGGER.debug("DDWrt.wan_dhcp_renew: Unable to renew DHCP lease from WAN interface (no data returned).")
            raise(DDWrt.DDWrtException("Unable to renew DHCP lease from WAN interface (no data returned)"))

        _LOGGER.debug("DDWrt.wan_dhcp_renew: succes.")
        return True


    def wan_pppoe_connect(self):
        """Connects the PPPoE WAN interface."""

        _LOGGER.debug("DDWrt.wan_pppoe_connect: Connecting PPPoE WAN interface...")

        url = f"{self._protocol}://{self._host}/{ENDPOINT_APPLY}"

        try:
            self.data = self._post_ddwrt_data(url, WAN_CONNECT_PPPOE_PARAMETERS)
        except Exception as e:
            _LOGGER.debug("DDWrt.pppoe_connect: Unable to send PPPoE WAN connect command.")
            raise(DDWrt.DDWrtException("Unable to send PPPoE WAN connect command: %s", e))

        if not self.data:
            _LOGGER.debug("DDWrt.pppoe_connect: Unable to connect from WAN PPPoE interface (no data returned).")
            raise(DDWrt.DDWrtException("Unable to connect from WAN PPPoE interface (no data returned)"))

        _LOGGER.debug("DDWrt.pppoe_disconnect: succes.")
        return True


    def wan_pppoe_disconnect(self):
        """Disconnects the PPPoE WAN interface."""

        _LOGGER.debug("DDWrt.wan_pppoe_disconnect: Disconnecting PPPoE WAN interface...")

        url = f"{self._protocol}://{self._host}/{ENDPOINT_APPLY}"

        try:
            self.data = self._post_ddwrt_data(url, WAN_DISCONNECT_PPPOE_PARAMETERS)
        except Exception as e:
            _LOGGER.debug("DDWrt.pppoe_disconnect: Unable to send PPPoE WAN disconnect command.")
            raise(DDWrt.DDWrtException("Unable to send PPPoE WAN disconnect command: %s", e))

        if not self.data:
            _LOGGER.debug("DDWrt.pppoe_disconnect: Unable to disconnect from WAN PPPoE interface (no data returned).")
            raise(DDWrt.DDWrtException("Unable to disconnect from WAN PPPoE interface (no data returned)"))

        _LOGGER.debug("DDWrt.pppoe_disconnect: succes.")
        return True


    def run_command(self, commands):
        """Execute a command on the router."""

        commands = commands.replace(' ', '+')
        commands = commands.replace('=', '%3D')
        commands = commands.replace('\n', '%0A')
        commands = commands.replace('\r', '%0D')

        url = f"{self._protocol}://{self._host}/{ENDPOINT_APPLY}"

        parameters = RUN_COMMAND_PARAMETERS.update({'ping_ip': commands})

        try:
            self.data = self._post_ddwrt_data(url, parameters)
        except Exception as e:
            _LOGGER.debug("DDWrt.run_command: Unable to send run_command.")
            raise(DDWrt.DDWrtException("Unable to send reboot command: %s", e))
            return None

        if not self.data:
            _LOGGER.debug("DDWrt.run_command: Rebooting router failed (no data returned).")
            raise(DDWrt.DDWrtException("Unable to run command (no data returned)"))

        _LOGGER.debug("DDWrt.run_command: succes.")
        return True


    def upnp_delete(self, rule='all'):
        """Delete an UPnP rule on the router."""

        url = f"{self._protocol}://{self._host}/{ENDPOINT_APPLY}"

        parameters = UPNP_DELETE_PARAMETERS.update({'remove': rule})

        try:
            self.data = self._post_ddwrt_data(url, parameters)
        except Exception as e:
            _LOGGER.debug("DDWrt.run_command: Unable to send upnp_delete.")
            raise(DDWrt.DDWrtException("Unable to send UPnP delete command: %s", e))
            return None

        if not self.data:
            _LOGGER.debug("DDWrt.run_command: Deleting UPnP rule failed (no data returned).")
            raise(DDWrt.DDWrtException("Unable to delete UPnP rule (no data returned)"))

        _LOGGER.debug("DDWrt.upnp_delete: succes.")
        return True


    def wake_on_lan(self, mac, network, port):
        """Perform a Wake-On-Lan on the router."""

        url = f"{self._protocol}://{self._host}/{ENDPOINT_APPLY}"

        parameters = RUN_COMMAND_PARAMETERS.update({
            'manual_wol_mac': mac,
            'manual_wol_network': network,
            'manual_wol_port': port,
        })

        try:
            self.data = self._post_ddwrt_data(url, parameters)
        except Exception as e:
            _LOGGER.debug("DDWrt.wake_on_lan: Unable to send Wake-On-Lan.")
            raise(DDWrt.DDWrtException("Unable to send Wake-On-Lan command: %s", e))
            return None

        if not self.data:
            _LOGGER.debug("DDWrt.wake_on_lan: Wake-On-Lan failed (no data returned).")
            raise(DDWrt.DDWrtException("Unable to run Wake-On-Lan (no data returned)"))

        _LOGGER.debug("DDWrt.wake_on_lan: succes.")
        return True


    def reboot(self):
        """Reboots the router."""

        url = f"{self._protocol}://{self._host}/{ENDPOINT_APPLY}"

        try:
            self.data = self._post_ddwrt_data(url, REBOOT_PARAMETERS)
        except Exception as e:
            _LOGGER.debug("DDWrt.reboot: Rebooting router failed.")
            raise(DDWrt.DDWrtException("Unable to send reboot command: %s", e))
            return None

        if not self.data:
            _LOGGER.debug("DDWrt.reboot: Rebooting router failed (no data returned).")
            raise(DDWrt.DDWrtException("Rebooting router failed (no data returned)"))

        _LOGGER.debug("DDWrt.reboot: succes.")
        return True


    def traffic_graph_url(self, convert):
        """Returns an URL to a traffic graph"""

        month = date.today().month
        year = date.today().year
        url = f"{self._protocol}://{self._host}/{ENDPOINT_TTGRAPH}?{month}-{year}"

        if convert:
            _LOGGER.debug("DDWrt.traffic_graph_url: Returning traffic graph image for %s", url)
            return _get_ddwrt_image(url)
        else:
            _LOGGER.debug("DDWrt.traffic_graph_url: Returning traffic graph URL: %s", url)
            return url


    # Make a GET request to the router
    def _get_ddwrt_data(self, url, convert):
        """Make a GET request to a DD-WRT router and return parsed result."""

        _LOGGER.debug("DDWrt._get_ddwrt_data: Connecting to %s", url)

        # Disable warning on not verifying the certificate
        if not self._verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        try:
            response = self._session.get(
                url = url,
                auth = (self._username, self._password),
                headers = {HTTP_X_REQUESTED_WITH: _X_REQUESTED_WITH},
                timeout = DEFAULT_TIMEOUT,
                verify = self._verify_ssl,
            )

            # Check if response indicates router is rebooting/busy
            if "The router is rebooting" in response.text:
                _LOGGER.warning("Router is currently rebooting, will retry later")
                raise DDWrt.ExceptionRouterBusy("Router is rebooting")

            if "Router is busy" in response.text:
                _LOGGER.warning("Router is busy, will retry later")
                raise DDWrt.ExceptionRouterBusy("Router is busy")

            return self._process_response(response, convert)

        except urllib3.exceptions.InsecureRequestWarning as e:
            _LOGGER.debug("DDWrt._get_ddwrt_data: Cannot verify certificate")
            raise(DDWrt.ExceptionCannotVerify(e))

        except SSLError as e:
            errmsg = str(e)

            # Check for hostname mismatch error
            if errmsg.startswith("hostname"):
                _LOGGER.debug("DDWrt._get_ddwrt_data: SSLError hostname mismatch")
                raise(DDWrt.ExceptionHostnameMismatch(e))

            # Get certificate from the router
            try:
                raw_cert = ssl.get_server_certificate((self._host, 443))
            except Exception as e:
                _LOGGER.debug("DDWrt._get_ddwrt_data: SSLError unknown error")
                raise(DDWrt.ExceptionSSLError(e))

            # Check for valid date in certificate
            x509 = crypto.load_certificate(crypto.FILETYPE_PEM, raw_cert)
            now = datetime.now()
            not_after = datetime.strptime(x509.get_notAfter().decode('utf-8'), "%Y%m%d%H%M%SZ")
            not_before = datetime.strptime(x509.get_notBefore().decode('utf-8'), "%Y%m%d%H%M%SZ")
            if now > not_after or now < not_before:
                _LOGGER.debug("DDWrt._get_ddwrt_data: SSLError invalid date")
                raise(DDWrt.ExceptionInvalidDate(e))

            # Return self-signed error
            _LOGGER.debug("DDWrt._get_ddwrt_data: SSLError self signed")
            raise(DDWrt.ExceptionSelfSigned(e))

        except ConnectionError as e:
            _LOGGER.debug("DDWrt._get_ddwrt_data: ConnectionError")
            raise(DDWrt.ExceptionConnectionError(e))

        except Timeout as e:
            _LOGGER.debug("DDWrt._get_ddwrt_data: Timeout")
            raise(DDWrt.ExceptionTimeout(e))

        except Exception as e:
            _LOGGER.debug("DDWrt._get_ddwrt_data: Unable to connect to the router Connection error: %s", e)
            raise(DDWrt.ExceptionUnknown(e))

    def _process_response(self, response, convert):
        """Process response from router."""

        if response.status_code == 200:
            if response.text:
                if convert:
                    result = dict(_DDWRT_DATA_REGEX.findall(response.text))
                else:
                    result = response.text
                _LOGGER.debug("DDWrt._get_ddwrt_data: received data: %s", result)
                return result
            else:
                _LOGGER.debug("DDWrt._get_ddwrt_data: Received empty response")
                raise(DDWrt.ExceptionEmptyResponse())

        if response.status_code == 401:
            _LOGGER.debug("DDWrt._get_ddwrt_data: Failed to authenticate")
            raise(DDWrt.ExceptionAuthenticationError())

        _LOGGER.debug("DDWrt._get_ddwrt_data: Invalid HTTP status code %s", response)
        raise(DDWrt.ExceptionHTTPError(response.status_code))


    # Make a POST request to the router
    def _post_ddwrt_data(self, url, data):
        """Make a POST request to a DD-WRT router."""

        _LOGGER.debug("DDWrt._post_ddwrt_data: Connecting to %s", url)

        # Disable warning on not verifying the certificate
        if not self._verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        try:
            response = self._session.post(
                url = url,
                auth = (self._username, self._password),
                data = data,
                headers = {HTTP_X_REQUESTED_WITH: _X_REQUESTED_WITH},
                timeout = DEFAULT_TIMEOUT,
                verify = self._verify_ssl,
            )
        except urllib3.exceptions.InsecureRequestWarning as e:
            _LOGGER.debug("DDWrt._post_ddwrt_data: Cannot verify certificate")
            raise(DDWrt.ExceptionCannotVerify(e))

        except SSLError as e:
            errmsg = str(e)

            # Check for hostname mismatch error
            if errmsg.startswith("hostname"):
                _LOGGER.debug("DDWrt._post_ddwrt_data: SSLError hostname mismatch")
                raise(DDWrt.ExceptionHostnameMismatch(e))

            # Get certificate from the router
            try:
                raw_cert = ssl.get_server_certificate((self._host, 443))
            except Exception as e:
                _LOGGER.debug("DDWrt._post_ddwrt_data: SSLError unknown error")
                raise(DDWrt.ExceptionSSLError(e))

            # Check for valid date in certificate
            x509 = crypto.load_certificate(crypto.FILETYPE_PEM, raw_cert)
            now = datetime.now()
            not_after = datetime.strptime(x509.get_notAfter().decode('utf-8'), "%Y%m%d%H%M%SZ")
            not_before = datetime.strptime(x509.getNotBefore().decode('utf-8'), "%Y%m%d%H%M%SZ")
            if now > not_after or now < not_before:
                _LOGGER.debug("DDWrt._post_ddwrt_data: SSLError invalid date")
                raise(DDWrt.ExceptionInvalidDate(e))

            # Return self-signed error
            _LOGGER.debug("DDWrt._post_ddwrt_data: SSLError self signed")
            raise(DDWrt.ExceptionSelfSigned(e))

        except ConnectionError as e:
            _LOGGER.debug("DDWrt._post_ddwrt_data: ConnectionError")
            raise(DDWrt.ExceptionConnectionError(e))

        except Timeout as e:
            _LOGGER.debug("DDWrt._post_ddwrt_data: Timeout")
            raise(DDWrt.ExceptionTimeout(e))

        except Exception as e:
            _LOGGER.debug("DDWrt._post_ddwrt_data: Unable to connect to the router Connection error: %s", e)
            raise(DDWrt.ExceptionUnknown(e))

        # Valid response
        if response.status_code == 200:
            _LOGGER.debug("DDWrt._post_ddwrt_data: Received valid response for %s", url)
            return True

        # Authentication error
        if response.status_code == 401:
            _LOGGER.debug("DDWrt._post_ddwrt_data: Failed to authenticate, please check your username and password")
            raise(DDWrt.ExceptionAuthenticationError())

        # Unknown HTTP error
        _LOGGER.debug("DDWrt._post_ddwrt_data: Invalid HTTP status code %s", response)
        raise(DDWrt.ExceptionHTTPError(response.status_code))


    # Return an image from the router by making a GET request
    def _get_ddwrt_image(self, url):
        """Make a GET request to a DD-WRT router and return parsed result."""

        _LOGGER.debug("DDWrt._get_ddwrt_image: Connecting to %s", url)

        # Disable warning on not verifying the certificate
        if not self._verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        try:
            response = self._session.get(
                url = url,
                auth = (self._username, self._password),
                headers = {HTTP_X_REQUESTED_WITH: _X_REQUESTED_WITH},
                timeout = DEFAULT_TIMEOUT,
                verify = self._verify_ssl,
            )
        except urllib3.exceptions.InsecureRequestWarning as e:
            _LOGGER.debug("DDWrt._get_ddwrt_image: Cannot verify certificate")
            raise(DDWrt.ExceptionCannotVerify(e))

        except SSLError as e:
            errmsg = str(e)

            # Check for hostname mismatch error
            if errmsg.startswith("hostname"):
                _LOGGER.debug("DDWrt._get_ddwrt_image: SSLError hostname mismatch")
                raise(DDWrt.ExceptionHostnameMismatch(e))

            # Get certificate from the router
            try:
                raw_cert = ssl.get_server_certificate((self._host, 443))
            except Exception as e:
                _LOGGER.debug("DDWrt._get_ddwrt_image: SSLError unknown error")
                raise(DDWrt.ExceptionSSLError(e))

            # Check for valid date in certificate
            x509 = crypto.load_certificate(crypto.FILETYPE_PEM, raw_cert)
            now = datetime.now()
            not_after = datetime.strptime(x509.get_notAfter().decode('utf-8'), "%Y%m%d%H%M%SZ")
            not_before = datetime.strptime(x509.getNotBefore().decode('utf-8'), "%Y%m%d%H%M%SZ")
            if now > not_after or now < not_before:
                _LOGGER.debug("DDWrt._get_ddwrt_image: SSLError invalid date")
                raise(DDWrt.ExceptionInvalidDate(e))

            # Return self-signed error
            _LOGGER.debug("DDWrt._get_ddwrt_image: SSLError self signed")
            raise(DDWrt.ExceptionSelfSigned(e))

        except ConnectionError as e:
            _LOGGER.debug("DDWrt._get_ddwrt_image: ConnectionError")
            raise(DDWrt.ExceptionConnectionError(e))

        except Timeout as e:
            _LOGGER.debug("DDWrt._get_ddwrt_image: Timeout")
            raise(DDWrt.ExceptionTimeout(e))

        except Exception as e:
            _LOGGER.debug("DDWrt._get_ddwrt_image: Unable to connect to the router Connection error: %s", e)
            raise(DDWrt.ExceptionUnknown(e))

        # Valid response
        if response.status_code == 200:
            if response.content:
                _LOGGER.debug("DDWrt._get_ddwrt_image: received image")
                return response.content
            else:
                _LOGGER.debug("DDWrt._get_ddwrt_image: Received empty response querying %s", url)
                raise(DDWrt.ExceptionEmptyResponse())

        # Authentication error
        if response.status_code == 401:
            _LOGGER.debug("DDWrt._get_ddwrt_image: Failed to authenticate, please check your username and password")
            raise(DDWrt.ExceptionAuthenticationError())

        # Unknown HTTP error
        _LOGGER.debug("DDWrt._get_ddwrt_image: Invalid HTTP status code %s", response)
        raise(DDWrt.ExceptionHTTPError(response.status_code))

    def _parse_wireless_clients_robust(self, active_clients):
        """
        Smart wireless client parsing that handles quoted CSV properly
        Returns a dictionary of wireless clients
        """
        import re

        if not active_clients:
            return {}

        # Parse the quoted CSV values properly using regex
        # This handles commas within quoted values correctly
        pattern = r"'([^']*?)'"
        elements = re.findall(pattern, active_clients)

        if not elements:
            _LOGGER.warning("No quoted elements found in active_wireless data")
            return {}

        total_elements = len(elements)
        _LOGGER.info("Found %s properly parsed wireless elements", total_elements)

        # Known field mappings for different positions
        # We'll map as many as we can recognize, and store the rest as extra fields
        field_mapping = {
            0: "mac",           # MAC address (required)
            1: "name",          # Device name
            2: "interface",     # Interface (wl0, wlan1, etc.)
            3: "uptime",        # Uptime (may contain commas!)
            4: "tx_rate",       # TX rate
            5: "rx_rate",       # RX rate
            6: "info",          # Additional info (HT20SGI, etc.)
            7: "signal",        # Signal strength
            8: "noise",         # Noise level
            9: "snr",           # Signal-to-noise ratio
            10: "signal_quality", # Signal quality
            # Positions 11+ are extra fields that vary by DD-WRT version
        }

        # We need at least MAC address (position 0)
        if total_elements < 1:
            _LOGGER.warning("Not enough elements for wireless client")
            return {}

        clients_wireless = {}

        # For now, assume one client per data set
        # (Multi-client parsing would need more sophisticated logic)
        client_data = {
            "type": CONF_TRACK_WIRELESS,
            "ap_mac": self.results.get("wl_mac", ""),
        }

        mac_address = None

        # Map known fields
        for i, value in enumerate(elements):
            field_name = field_mapping.get(i)

            if field_name == "mac":
                mac_address = value
            elif field_name == "name":
                client_data["name"] = value
                client_data["radioname"] = value  # Duplicate for compatibility
            elif field_name and field_name in ["interface", "uptime", "tx_rate", "rx_rate", "info", "signal", "noise", "snr", "signal_quality"]:
                client_data[field_name] = value
            else:
                # Store unknown fields as extra_N
                client_data["extra_{}".format(i)] = value

        if mac_address:
            clients_wireless[mac_address] = client_data
            _LOGGER.info("Parsed wireless client %s with %s fields", mac_address, total_elements)
        else:
            _LOGGER.warning("No MAC address found in wireless client data")

        return clients_wireless

    def _parse_dhcp_leases_robust(self, active_clients):
        """
        Smart DHCP lease parsing using IP addresses as anchor points
        Strategy: Find IP addresses, then extract fields at known offsets relative to IP position
        Returns a dictionary of DHCP clients
        """
        import re

        if not active_clients:
            return {}

        # Parse the quoted CSV values properly using regex
        # This handles commas within quoted values correctly
        pattern = r"'([^']*?)'"
        elements = re.findall(pattern, active_clients)

        if not elements:
            _LOGGER.warning("No quoted elements found in dhcp_leases data")
            return {}

        total_elements = len(elements)
        _LOGGER.debug("Found %s properly parsed DHCP lease elements", total_elements)

        # IP address pattern - matches standard IPv4 addresses
        ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')

        clients_dhcp = {}
        entry_count = 0

        # Find all IP addresses and use them as anchors
        for i, element in enumerate(elements):
            if ip_pattern.match(element):
                try:
                    # IP found at position i, extract fields at known offsets
                    ip = element                    # Current position
                    hostname = elements[i - 1] if i >= 1 else ""      # IP - 1
                    mac = elements[i + 1] if i + 1 < total_elements else ""       # IP + 1
                    expiration = elements[i + 2] if i + 2 < total_elements else "" # IP + 2

                    if mac and ip:  # Only add if we have essential fields
                        clients_dhcp[mac] = {
                            "name": hostname,
                            "type": CONF_TRACK_DHCP,
                            "ip": ip,
                            "hostname": hostname,
                            "lease_expiration": expiration
                        }
                        entry_count += 1
                        _LOGGER.debug("DHCP Entry %s: hostname='%s', ip='%s', mac='%s', expiration='%s'",
                                    entry_count, hostname, ip, mac, expiration)

                except IndexError as e:
                    _LOGGER.warning("Error parsing DHCP lease entry at IP position %s: %s", i, e)
                    continue

        _LOGGER.debug("Parsed %s DHCP lease entries using IP anchor method", entry_count)
        return clients_dhcp

    def _parse_pppoe_leases_robust(self, active_clients):
        """
        Smart PPPoE lease parsing that handles quoted CSV properly
        Returns a dictionary of PPPoE clients
        """
        import re

        if not active_clients:
            return {}

        # Parse the quoted CSV values properly using regex
        pattern = r"'([^']*?)'"
        elements = re.findall(pattern, active_clients)

        if not elements:
            _LOGGER.warning("No quoted elements found in pppoe_leases data")
            return {}

        total_elements = len(elements)
        _LOGGER.debug("Found %s properly parsed PPPoE lease elements", total_elements)

        # PPPoE leases expect 3 fields: Interface | Username | Local IP
        if total_elements % 3 != 0:
            _LOGGER.warning("PPPoE lease data doesn't divide evenly by 3. Total elements: %s", total_elements)
            # Try to recover by truncating to nearest multiple of 3
            total_elements = (total_elements // 3) * 3

        clients_pppoe = {}

        for i in range(0, total_elements, 3):
            try:
                interface = elements[i]
                username = elements[i + 1]
                local_ip = elements[i + 2]

                if local_ip:  # Use local_ip as key
                    clients_pppoe[local_ip] = {
                        "name": username,
                        "type": CONF_TRACK_PPPOE,
                        "interface": interface,
                        "username": username,
                        "local_ip": local_ip
                    }

            except IndexError as e:
                _LOGGER.warning("Error parsing PPPoE lease entry at index %s: %s", i, e)
                continue

        _LOGGER.debug("Parsed %s PPPoE lease entries", len(clients_pppoe))
        return clients_pppoe

    def _parse_pptp_leases_robust(self, active_clients):
        """
        Smart PPTP lease parsing that handles quoted CSV properly
        Returns a dictionary of PPTP clients
        """
        import re

        if not active_clients:
            return {}

        # Parse the quoted CSV values properly using regex
        pattern = r"'([^']*?)'"
        elements = re.findall(pattern, active_clients)

        if not elements:
            _LOGGER.warning("No quoted elements found in pptp_leases data")
            return {}

        total_elements = len(elements)
        _LOGGER.debug("Found %s properly parsed PPTP lease elements", total_elements)

        # PPTP leases expect 4 fields: Interface | Username | Local IP | Remote IP
        if total_elements % 4 != 0:
            _LOGGER.warning("PPTP lease data doesn't divide evenly by 4. Total elements: %s", total_elements)
            # Try to recover by truncating to nearest multiple of 4
            total_elements = (total_elements // 4) * 4

        clients_pptp = {}

        for i in range(0, total_elements, 4):
            try:
                interface = elements[i]
                username = elements[i + 1]
                local_ip = elements[i + 2]
                remote_ip = elements[i + 3]

                if local_ip:  # Use local_ip as key
                    clients_pptp[local_ip] = {
                        "name": username,
                        "type": CONF_TRACK_PPTP,
                        "interface": interface,
                        "username": username,
                        "local_ip": local_ip,
                        "remote_ip": remote_ip
                    }

            except IndexError as e:
                _LOGGER.warning("Error parsing PPTP lease entry at index %s: %s", i, e)
                continue

        _LOGGER.debug("Parsed %s PPTP lease entries", len(clients_pptp))
        return clients_pptp

    def _parse_arp_table_robust(self, active_clients):
        """
        Smart ARP table parsing using IP addresses as anchor points
        Strategy: Find IP addresses, then extract fields at known offsets relative to IP position
        Returns a dictionary of ARP clients
        """
        import re

        if not active_clients:
            return {}

        # Parse the quoted CSV values properly using regex
        pattern = r"'([^']*?)'"
        elements = re.findall(pattern, active_clients)

        if not elements:
            _LOGGER.warning("No quoted elements found in arp_table data")
            return {}

        total_elements = len(elements)
        _LOGGER.debug("Found %s properly parsed ARP table elements", total_elements)

        # IP address pattern - matches standard IPv4 addresses
        ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')

        clients_arp = {}
        entry_count = 0

        # Find all IP addresses and use them as anchors
        for i, element in enumerate(elements):
            if ip_pattern.match(element):
                try:
                    # IP found at position i, extract fields at known offsets
                    ip = element                    # Current position
                    hostname = elements[i - 1] if i >= 1 else ""      # IP - 1
                    mac = elements[i + 1] if i + 1 < total_elements else ""       # IP + 1
                    connections = elements[i + 2] if i + 2 < total_elements else "" # IP + 2
                    interface = elements[i + 3] if i + 3 < total_elements else ""   # IP + 3

                    if mac and ip:  # Only add if we have essential fields
                        clients_arp[mac] = {
                            "name": hostname,
                            "type": CONF_TRACK_ARP,
                            "ip": ip,
                            "hostname": hostname,
                            "connections": connections,
                            "interface": interface
                        }
                        entry_count += 1
                        _LOGGER.debug("ARP Entry %s: hostname='%s', ip='%s', mac='%s', connections='%s', interface='%s'",
                                    entry_count, hostname, ip, mac, connections, interface)

                except IndexError as e:
                    _LOGGER.warning("Error parsing ARP entry at IP position %s: %s", i, e)
                    continue

        _LOGGER.debug("Parsed %s ARP entries using IP anchor method", entry_count)
        return clients_arp

    def _get_parameter(self, py_parameter, router_parameter):
        if router_parameter in self.data:
            self.results.update({py_parameter: self.data.pop(router_parameter)})
            if self.results[py_parameter] == "":
                self.results.update({py_parameter: None})


    class DDWrtException(Exception):
        pass

    class ExceptionAuthenticationError(Exception):
        pass

    class ExceptionEmptyResponse(Exception):
        pass

    class ExceptionHTTPError(Exception):
        pass

    class ExceptionSSLError(Exception):
        pass

    class ExceptionConnectionError(Exception):
        pass

    class ExceptionInvalidDate(Exception):
        pass

    class ExceptionSelfSigned(Exception):
        pass

    class ExceptionCannotVerify(Exception):
        pass

    class ExceptionHostnameMismatch(Exception):
        pass

    class ExceptionUnknown(Exception):
        pass

    class ExceptionTimeout(Exception):
        pass

    class ExceptionRouterBusy(DDWrtException):
        """Raised when router is busy/rebooting."""
        pass

