# Windows Firewall Spam Blocker

Superseded by [STOMP](https://github.com/Blasman/Stop_Troublemakers_On_My_Port).

A GUI application that will reveal the first detected remote IP address that sends/receives a user-defined number of network packets for a user-defined protocol and port number. In addition, it gives the option to block the IP address in Windows Firewall by setting both inbound and outbound traffic rules.

## Limitations

Only listens on one network device.
Only listens/blocks one protocol.
Only listens/blocks one port.

## Requirements

- [Npcap](https://npcap.com/#download)
- If running the .py script, install required python packages with cmd `pip install scapy pyperclip wmi`

## Config Settings

Default config.ini file:
```[Settings]
# REQUIRED SETTINGS:
PROTOCOL = UDP               # Protocol to monitor (UDP/TCP)
PORT =                       # Port number to monitor
FOUND_PACKETS_REQUIRED = 25  # Number of packets to confirm match
TIMEOUT_SECONDS = 5          # Timeout in seconds for detection

# OPTIONAL SETTINGS:
FIREWALL_RULE_BASENAME =     # Optional prefix for final firewall rule name
ADDITIONAL_BPF_FILTER =      # Optional additional BPF filter rules
NETWORK_INTERFACE =          # Network interface name (leave blank for selection)
```

`FOUND_PACKETS_REQUIRED` includes both inbound and outbound traffic.

`FIREWALL_RULE_BASENAME` will be prefixed to the *final* firewall rule name *after* you fill out the "Firewall rule name" input box.

`ADDITONAL_BPF_FILTER` allows you to set more [BPF filters](https://www.ibm.com/docs/en/qsip/7.4?topic=queries-berkeley-packet-filters).

`NETWORK_INTERFACE` uses the Npcap network device name. Leave this blank to have the app prompt you to select a network device (by friendly Windows name + Npcap name) that will be saved to config.

## Screenshots

![Scanning](https://i.imgur.com/LjWk9SY.png)
![Found IP](https://i.imgur.com/9zusmy3.png)
