"""DD-WRT device tracker - Eelco Huininga 2019-2020."""

from datetime import datetime
import logging
from typing import Dict

from homeassistant.components.device_tracker import SourceType
from homeassistant.components.device_tracker.config_entry import ScannerEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import callback, HomeAssistant
from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC
from homeassistant.helpers.dispatcher import async_dispatcher_connect

from . import (
    ATTR_ATTRIBUTION,
    ATTR_FRIENDLY_NAME,
    ATTR_ICON,
    ATTR_WIRED,
    ATTRIBUTION,
    CONF_HOST,
    DEFAULT_DEVICE_NAME,
    DEVICE_TRACKERS,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass, config_entry, async_add_entities):
    """Set up the DD-WRT device tracker."""

    _LOGGER.debug("device_tracker::async_setup_entry start")
    router = hass.data[DOMAIN][config_entry.data[CONF_HOST]]['entity']
    tracked = set()

    @callback
    def update_router():
        """Update the values of the router."""
        _LOGGER.debug("device_tracker::async_setup_entry::update_router")
        add_entities(
            hass.data[DOMAIN][config_entry.data[CONF_HOST]]['entity'],
            async_add_entities,
            tracked
        )

    router.listeners.append(
        async_dispatcher_connect(hass, router.signal_device_new, update_router)
    )

    update_router()


@callback
def add_entities(router, async_add_entities, tracked):
    """Add new tracker entities from the router."""
    _LOGGER.debug("device_tracker::add_entities start")
    new_tracked = []

    _LOGGER.debug("device_tracker::add_entities router=%s", router)
    for mac, details in router.devices.items():
        _LOGGER.debug("device_tracker::add_entities mac=%s details=%s", mac, details)
        if mac in tracked:
            continue

        new_tracked.append(DdwrtDevice(router, mac, details))
        tracked.add(mac)

    if new_tracked:
        async_add_entities(new_tracked, True)


class DdwrtDevice(ScannerEntity):
    """Representation of a DD-WRT client device."""

    def __init__(self, router, mac, details):
        """Initialize a DD-WRT client device."""

        _LOGGER.debug("DdwrtDevice::__init__")

        self._router = router
        self._details = details
        self._friendly_name = details["name"] or DEFAULT_DEVICE_NAME
        self._mac = mac
        self._manufacturer = None
        self._model = None
        self._icon = None
        self._is_wired = None
        self._active = True
        self._attrs = {}

        self._unsub_dispatcher = None

        # Initialize device properties from the details
        self.update()

    def update(self) -> None:
        """Update the DD-WRT device."""

        _LOGGER.debug("DdwrtDevice::update details=%s", self._details)

        self._icon = DEVICE_TRACKERS[self._details["type"]][ATTR_ICON]
        self._is_wired = DEVICE_TRACKERS[self._details["type"]][ATTR_WIRED]

        # Check if device is still in the router's device list (active)
        device = self._router.devices.get(self._mac)
        if device:
            self._active = True
            self._details = device

            # Try to determine manufacturer from MAC address
            self._manufacturer = self._get_manufacturer_from_mac(self._mac)


            # Update friendly name if we have a hostname
            hostname = device.get("hostname", "")
            if hostname and hostname != "*" and hostname != "":
                self._friendly_name = hostname
            else:
                self._friendly_name = self._mac

            # Update attributes with current device data
            self._attrs = {
                "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ip_address": device.get("ip", ""),
                "hostname": device.get("hostname", ""),
                "mac_address": self._mac,
                "connections": device.get("connections", ""),
                "interface": device.get("interface", ""),
                "connection_type": "Wired" if self._is_wired else "Wireless",
                "device_type": device.get("type", "").replace("_clients", "").upper()
            }
        else:
            # Device not in current scan, mark as inactive
            self._active = False

    def _get_manufacturer_from_mac(self, mac):
        """Try to determine manufacturer from MAC address OUI."""
        if not mac:
            return None

        # Get the first 3 octets (OUI - Organizationally Unique Identifier)
        oui = mac.upper().replace(":", "")[:6]

        # Common manufacturer OUIs (this is a small sample - in a real implementation
        # you might want to use a full OUI database)
        oui_manufacturers = {
            "3CA6F6": "Apple",
            "5C3E1B": "Apple",
            "FC66CF": "Apple",
            "1CB3C9": "Apple",
            "DCA904": "Apple",
            "A248F8": "Apple",
            "0C4DE9": "Apple",
            "E8039A": "Raspberry Pi Foundation",
            "B827EB": "Raspberry Pi Foundation",
            "7CF17E": "Raspberry Pi Foundation",
            "50EC50": "Roborock",
            "645725": "Reolink",
            "D07602": "Reolink",
            "ECE512": "Tado",
            "80691A": "Linksys",
            "A83B76": "Brother",
            "C0F853": "Tuya",
            "349B7A": "Sonoff",
            "20BBBC": "EZVIZ",
            "249494": "Shenzhen",
            "00037F": "Atheros",
            "7CA449": "Samsung",
            "709741": "LG",
            "7C6166": "Amazon",
            "0003F7": "Amazon"
        }

        return oui_manufacturers.get(oui, None)

    @property
    def device_info(self):
        """Return the device info."""
        # Use current IP address if available
        current_ip = self._details.get("ip", "") if hasattr(self, '_details') else ""

        result = {
            "connections": {(CONNECTION_NETWORK_MAC, self._mac)},
            "identifiers": {(DOMAIN, self.unique_id)},
            "manufacturer": self._manufacturer,
            "model": self._model,
            "name": self._friendly_name,
            "via_device": (DOMAIN),
        }
        _LOGGER.debug("DdwrtDevice::device_info result=%s", result)
        return result

    @property
    def unique_id(self) -> str:
        """Return a unique ID."""

        _LOGGER.debug("DdwrtDevice::unique_id mac=%s", self._mac)

        return self._mac

    @property
    def name(self) -> str:
        """Return the name."""

        _LOGGER.debug("DdwrtDevice::name friendly_name=%s", self._friendly_name)

        return self._friendly_name

    @property
    def is_connected(self):
        """Return true if the device is connected to the network."""

        _LOGGER.debug("DdwrtDevice::is_connected mac=%s active=%s", self._mac, self._active)

        return self._active

    @property
    def source_type(self) -> str:
        """Return the source type."""

        _LOGGER.debug("DdwrtDevice::source_type mac=%s", self._mac)

        return SourceType.ROUTER

    @property
    def icon(self) -> str:
        """Return the icon."""

        _LOGGER.debug("DdwrtDevice::icon mac=%s", self._mac)

        return self._icon

    @property
    def device_state_attributes(self) -> Dict[str, any]:
        """Return the attributes."""

        _LOGGER.debug("DdwrtDevice::attributes mac=%s", self._mac)

        attributes = {
            ATTR_ATTRIBUTION: ATTRIBUTION,
            "mac_address": self._mac,
            "is_wired": self._is_wired,
        }

        # Add current device details
        if hasattr(self, '_details') and self._details:
            attributes.update({
                "ip_address": self._details.get("ip", ""),
                "hostname": self._details.get("hostname", ""),
                "interface": self._details.get("interface", ""),
                "connections": self._details.get("connections", ""),
                "device_type": self._details.get("type", "").replace("_clients", "").upper()
            })

        # Add additional attributes
        attributes.update(self._attrs)

        return attributes

    @property
    def should_poll(self) -> bool:
        """No polling needed."""

        _LOGGER.debug("DdwrtDevice::should_poll mac=%s", self._mac)

        return False

    async def async_on_demand_update(self):
        """Update state."""

        _LOGGER.debug("DdwrtDevice::async_on_demand_update mac=%s", self._mac)

        # Update device state from router data
        self.update()

        self.async_schedule_update_ha_state(True)

    async def async_added_to_hass(self):
        """Register state update callback."""

        _LOGGER.debug("DdwrtDevice::async_added_to_hass mac=%s", self._mac)

        self._unsub_dispatcher = async_dispatcher_connect(
            self.hass, self._router.signal_device_update, self.async_on_demand_update
        )

    async def async_will_remove_from_hass(self):
        """Clean up after entity before removal."""

        _LOGGER.debug("DdwrtDevice::async_will_remove_from_hass mac=%s", self._mac)

        if self._unsub_dispatcher:
            self._unsub_dispatcher()


def icon_for_freebox_device(device) -> str:
    """Return a host icon from his type."""
    return DEVICE_ICONS.get(device["host_type"], "mdi:help-network")

