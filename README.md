# DD-WRT Home Assistant Integration - Enhanced Fork

## What is this?

This is an enhanced fork of the [DD-WRT Home Assistant integration](https://github.com/kimballen/home-assistant-ddwrt) that fixes critical parsing errors affecting device detection in newer DD-WRT firmware versions.

## Why this fork exists

The original integration might have worked well with older DD-WRT versions, but with newer firmwares (particularly mine, v3.0-r53562 released in 2023) it was showing various parsing failures, which means the integration didn't really work well in Home Assistant.

### Issues Fixed
- DHCP lease parsing errors preventing device detection
- ARP table parsing failures due to format changes
- Wireless client parsing problems with comma-separated values
- WAN status misreporting connection state

## Target Environment
- **DD-WRT Firmware**: Specifically tested on v3.0-r53562 std (released 2023/03/10)
- **Symptoms**: Integration errors in Home Assistant logs, missing devices in device tracker
- **Goal**: Restore reliable device detection for presence sensing
- **Status**: Major parsing issues resolved for the tested firmware version

**Important**: This fork is primarily designed to work with DD-WRT v3.0-r53562. While the enhanced parsing methods may work with other versions, no guarantees are provided for newer or older DD-WRT releases as data formats may have changed.

## IP Anchor-Based Parsing
Instead of counting fields or using separators, we use IP addresses as anchor points to locate other data fields.

#### How It Works
1. Parse all quoted fields using regex `r"'([^']*?)'"`
2. Find IP addresses using pattern `^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$`
3. Extract fields at predictable offsets relative to each IP position

#### Benefits
- Less dependent on exact field counts
- Uses natural data structure patterns
- Handles missing fields gracefully
- Adapts to field count variations

## Fixes Implemented

### Error Patterns fixed
- `invalid number of elements in dhcp_leases (expected 5, found X)`
- `invalid number of elements in arp_table (expected 4-5, found X)`
- `invalid number of elements in active_wireless (expected 11, found X)`

### 1. DHCP Lease Parsing
- **Error**: `update_lan_data(): invalid number of elements in dhcp_leases (expected 5, found 217)`
- **Root Cause**: Multiple devices with 7 fields each, but parser expected multiples of 5
- **Example Data**: `'Phone-John','192.168.1.100','AA:BB:CC:DD:EE:FF','0 days 12:34:56','100','br0',''`
- **Solution**: IP anchor-based parsing
- **Result**: All DHCP clients now parsed correctly

```python
# IP Anchor Strategy for DHCP
ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
for i, element in enumerate(elements):
    if ip_pattern.match(element):
        ip = element                    # Current position
        hostname = elements[i - 1]      # IP - 1
        mac = elements[i + 1]           # IP + 1
        expiration = elements[i + 2]    # IP + 2
```

### 2. ARP Table Parsing
- **Error**: Expected 4-5 fields, but router returns 8 fields per entry
- **Example Data**: `'Laptop-Jane','192.168.1.101','11:22:33:44:55:66','5','br0','1234567890','987654321','1122334455'`
- **Solution**: IP anchor-based parsing to extract meaningful fields

```python
# IP Anchor Strategy for ARP
ip = element                    # Current position
hostname = elements[i - 1]      # IP - 1
mac = elements[i + 1]           # IP + 1
connections = elements[i + 2]   # IP + 2
interface = elements[i + 3]     # IP + 3
# Traffic stats automatically ignored
```

### 3. Wireless Client Parsing
- **Error**: `update_wireless_data(): invalid number of elements in active_wireless (expected 11, found 18)`
- **Root Cause**: Commas within quoted values like `'2 days, 15:30:45'`
- **Solution**: Regex-based quoted CSV parsing with flexible field mapping

### 4. WAN Status Parsing
- **Issue**: Router reports "error" status even when connected with valid IP
- **Enhancement**: Intelligent status correction based on actual IP configuration

### 5. Device Tracker Fixes
- **Issue**: All devices showing as "Away" with "detected at unavailable" messages in Home Assistant
- **Root Cause**: Device tracker was hardcoded to mark all devices as inactive (`self._active = False`)
- **Solution**: Proper device state management based on ARP table presence

#### Device Tracker Improvements
- **Proper Connectivity Status**: Devices in ARP table now show as "Home" instead of "Away"
- **Automatic Manufacturer Detection**: MAC OUI lookup for Apple, Linksys, Reolink, etc.
- **Enhanced Device Properties**:
  - IP addresses, hostnames, connection counts
  - Network interface information (br0, wlan1, etc.)
  - Connection type (Wired/Wireless)
  - Last seen timestamps
- **Smart Device Naming**: Uses hostnames when available, falls back to MAC addresses
- **Real-time Updates**: Device state updates when router is polled

## Testing

Enhanced test suite included (`test_integration.py`) with detailed device output:

```
Testing LAN Data...
LAN data retrieved successfully
   ARP Clients: 15
   DHCP Clients: 23

   DHCP Client Details:
       1. MAC: AA:BB:CC:DD:EE:FF
          Hostname: 'Phone-John'
          IP: 192.168.1.100
          Lease: 0 days 12:34:56
```

## Installation

1. **Backup your current integration**
2. **Add this repository to HACS***
    - **or replace the files** in your `custom_components/ddwrt/` directory with the files from this fork
3. **Restart Home Assistant**
4. **Check logs** to verify parsing errors are eliminated
5. **Verify device detection** in the device tracker

## Files Modified

- **`custom_components/ddwrt/pyddwrt.py`**: Enhanced parsing methods
- **`custom_components/ddwrt/device_tracker.py`**: Fixed device connectivity status and enhanced properties
- **`custom_components/ddwrt/__init__.py`**: Added device update signals and dispatcher logic
- **`test_integration.py`**: Comprehensive testing suite

## Notes

- Field count assumptions removed to handle format variations within this version
- Enhanced error handling for missing or malformed data
- While parsing is more robust, compatibility with newer DD-WRT versions is not guaranteed
- No user support is provided for this fork
