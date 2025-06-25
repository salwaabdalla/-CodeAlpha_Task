# -CodeAlpha_Task
Simple network sniffer written in python
This is a basic network packet sniffer written in Python using the **Scapy** library. It captures IP packets on your network interface and prints key information such as source and destination IP addresses, the transport protocol (TCP/UDP), and a snippet of the payload.

---

## Features

- Captures live IP packets on the network
- Displays source and destination IP addresses
- Identifies the transport layer protocol (TCP or UDP)
- Prints the first 50 bytes of the TCP payload (if available)
- Runs in the terminal with a simple output format

---

## Requirements

- Python 3.x
- [Scapy](https://scapy.net/)

You can install Scapy with pip:

```bash
pip install scapy
