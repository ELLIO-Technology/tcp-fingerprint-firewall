# Recon Shield / TCP Fingerprint Firewall

```
 ████████╗ ██████╗██████╗     ███████╗██╗███╗   ██╗ ██████╗ ███████╗██████╗ ██████╗ ██████╗ ██╗███╗   ██╗████████╗
 ╚══██╔══╝██╔════╝██╔══██╗    ██╔════╝██║████╗  ██║██╔════╝ ██╔════╝██╔══██╗██╔══██╗██╔══██╗██║████╗  ██║╚══██╔══╝
    ██║   ██║     ██████╔╝    █████╗  ██║██╔██╗ ██║██║  ███╗█████╗  ██████╔╝██████╔╝██████╔╝██║██╔██╗ ██║   ██║   
    ██║   ██║     ██╔═══╝     ██╔══╝  ██║██║╚██╗██║██║   ██║██╔══╝  ██╔══██╗██╔═══╝ ██╔══██╗██║██║╚██╗██║   ██║   
    ██║   ╚██████╗██║         ██║     ██║██║ ╚████║╚██████╔╝███████╗██║  ██║██║     ██║  ██║██║██║ ╚████║   ██║   
    ╚═╝    ╚═════╝╚═╝         ╚═╝     ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝   ╚═╝   
 ███████╗██╗██████╗ ███████╗██╗    ██╗ █████╗ ██╗     ██╗                                                         
 ██╔════╝██║██╔══██╗██╔════╝██║    ██║██╔══██╗██║     ██║                                                         
 █████╗  ██║██████╔╝█████╗  ██║ █╗ ██║███████║██║     ██║                                                         
 ██╔══╝  ██║██╔══██╗██╔══╝  ██║███╗██║██╔══██║██║     ██║                                                         
 ██║     ██║██║  ██║███████╗╚███╔███╔╝██║  ██║███████╗███████╗                                                    
 ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝                                                    
```

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/ELLIO-Technology/tcp-fingerprint-firewall/actions)
[![License: AGPL v3 / Propreitary](https://img.shields.io/badge/License-Dual_AGPL%20v3_/_Proprietary-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Kernel: 5.5+](https://img.shields.io/badge/Kernel-5.5%2B-orange.svg)](https://www.kernel.org/)
[![Security: Fingerprinting](https://img.shields.io/badge/Security-Fingerprinting-red.svg)](https://github.com/ELLIO-Technology/tcp-fingerprint-firewall)
[![eBPF: XDP](https://img.shields.io/badge/eBPF-XDP-blueviolet.svg)](https://ebpf.io/what-is-ebpf/)

![TCP Fingerprint Firewall in action](screenshots/status.png "TCP Fingerprint Firewall in action")


## Demo
[Check the demo](screenshots/demo.mp4)


## Protection Against Reconnaissance

**Recon Shield** operates as a practical security tool that leverages [MuonFP](https://github.com/sundruid/muonfp) for TCP fingerprinting, combined with Linux kernel's eBPF/XDP capability to **intercept and analyze packet traffic at wire speed** before it reaches your network stack.

While MuonFP helps identify and classify network traffic based on TCP fingerprints, **Recon Shield** takes this a step further by actively blocking adversaries during the reconnaissance phase. By recognizing the unique TCP "fingerprints" of scanning tools, it prevents them from mapping your infrastructure in the first place.

## Understanding TCP Fingerprints

![Real-time monitoring dashboard](screenshots/monitoring.png "Real-time monitoring dashboard")

Every day, thousands of automated scanners probe the internet looking for vulnerable systems. What many security practitioners don't realize is that these scanners can be identified by their distinctive TCP fingerprints, such as specific window sizes, option combinations, and other TCP header characteristics.

Recon Shield demonstrates how these fingerprints can be used not just for identification but for active defense - **preventing reconnaissance tools from gathering information about your services**. For more on why this matters, see Ken Webster's article ["There is No Such Thing as a 'Benign' Internet Scanner"](https://www.kenwebster.com/index.php/2025/01/29/there-is-no-such-thing-as-a-benign-internet-scanner/).

## Core Capabilities

- **MuonFP Integration**: Built on Ken Webster's MuonFP methodology for TCP fingerprinting, providing robust identification of network traffic
- **Advanced Fingerprint Analysis**: Utilizes window size, TCP options, MSS, and window scale for comprehensive traffic classification
- **eBPF-Powered Performance**: Uses XDP (eXpress Data Path) for kernel-level packet filtering with minimal overhead
- **Zero Network Stack Impact**: Processes packets before they reach your applications
- **Wildcard Pattern Matching**: Flexible fingerprint definitions with wildcard support
- **Real-Time Monitoring Dashboard**: Watch TCP fingerprint matches in real-time with the ncurses monitoring UI
- **Kernel-Optimized**: Hand-tuned code that satisfies the strict eBPF verifier requirements


## Beyond Blocking: TCP Fingerprinting Applications

While Recon Shield demonstrates how TCP fingerprinting can be used to block reconnaissance, the underlying MuonFP technology has broader security applications:

- **Threat Intelligence**: Identifying and categorizing traffic by source tools and intentions
- **Traffic Characterization**: Understanding the nature of network connections based on their TCP signatures
- **Security Research**: Analyzing how different tools and systems interact with networks
- **Attribution**: Connecting scanning activities to specific tools, techniques, and potentially threat actors
- **Network Visibility**: Gaining deeper insights into the types of systems connecting to your infrastructure

## Proactive Security Approach

Traditional firewalls typically react after reconnaissance has already occurred. Recon Shield demonstrates a different approach:

1. **Early Detection**: Identify scanning attempts based on TCP fingerprints before network mapping occurs
2. **Silent Response**: Process packets at the kernel level without response, preventing scanners from confirming your existence
3. **Traffic Analysis**: Gain insights about potential threats by monitoring the types of tools attempting to scan your systems
4. **Adaptive Protection**: Update fingerprint patterns as new scanning methodologies emerge

## Getting Started

```bash
# Clone repository
git clone https://github.com/ellio-tech/tcp-fingerprint-firewall.git
cd tcp-fingerprint-firewall

# Install and build (requires Linux kernel 5.5+)
sudo ./install.sh

# Load the firewall on your network interface
sudo ./build/load_firewall.sh eth0

# Monitor TCP fingerprint matches in real-time
sudo ./build/tcp-monitor eth0
```



## Advanced Configuration

Recon Shield offers precise control over TCP fingerprint matching and actions:

```bash
# Block Masscan scanner fingerprints
sudo ./build/tcp-firewall eth0 add "1024:::" DROP

# Block packets with specific option patterns (this example will drop legitimate traffic as well)
sudo ./build/tcp-firewall eth0 add "*:2-4-8-1-3:1460:7" DROP
```

These configurations allow you to selectively target specific scanning tools based on their TCP fingerprints while minimizing impact on legitimate traffic.

## Documentation & Educational Resources

This project includes detailed documentation for both practical deployment and educational purposes:

### Project Documentation
- [USAGE.md](USAGE.md) - Quick reference and command listing
- [User Manual](user-manual.md) - Complete usage documentation
- [Fingerprint Format](fingerprint-format.md) - Creating custom fingerprint patterns
- [Installation Guide](installation.md) - Detailed installation instructions
- [Troubleshooting Guide](troubleshooting.md) - Solutions for common issues
- [README-MONITOR.md](README-MONITOR.md) - Documentation for the monitoring tool

### Learning Resources
- ["There is No Such Thing as a 'Benign' Internet Scanner"](https://www.kenwebster.com/index.php/2025/01/29/there-is-no-such-thing-as-a-benign-internet-scanner/) - Ken Webster's article on scanner risks
- ["IP Blocking vs TCP Fingerprint Blocking: How to Use and Combine Them"](https://blog.ellio.tech/ip-blocking-vs-tcp-fingerprint-blocking-how-to-use-and-combine-them/) - Comparing blocking methodologies
- [MuonFP Project](https://github.com/sundruid/muonfp) - The fingerprinting methodology that powers Recon Shield

## Security Philosophy & Research Goals

Recon Shield represents both a practical security tool and a research project to demonstrate the value of TCP fingerprinting. Our approach is built around these principles:

1. **Advancing TCP Fingerprinting**: Demonstrating how fingerprinting can enhance security beyond traditional methods
2. **Proactive Defense**: Showing how identifying reconnaissance tools early prevents later attack stages
3. **Performance & Practicality**: Proving that advanced security techniques can be implemented without performance impacts
4. **Open Research**: Sharing knowledge about TCP fingerprinting through open-source code and educational materials
5. **Adaptability**: Exploring how fingerprinting techniques can evolve to address new scanning methodologies

[//]: # (## 🌐 Real-World Impact - COMING SOON)  

[//]: # ()
[//]: # (Organizations deploying TCP Fingerprint Firewall have reported:)

[//]: # ()
[//]: # (- **90% reduction** in reconnaissance traffic)

[//]: # (- **65% decrease** in overall attack attempts)

[//]: # (- **Zero successful** reconnaissance from common scanning tools)

[//]: # (- **Invisible infrastructure** to automated internet scanners)

## Known Issues

- **TCP Option Ordering Bug**: Currently, TCP options are sometimes sorted in ascending order when displayed, rather than preserving their original sequence from the packet. This affects only the display in the monitoring tool, not the actual fingerprint matching.

## Roadmap & Future Development

The future of this project includes:

- **Normalize the name of the tool**: Use "Recon Shield" as an official name of the tool
- **Enhanced TCP Fingerprinting**: Advanced techniques for more accurate identification
- **Fingerprint Learning**: Automatic pattern generation from traffic analysis
- **Cloud-Native Deployment**: Kubernetes operator for cloud infrastructure protection
- **Hardware Offloading**: Support for NICs with XDP offload capabilities

## Contributors

This project is made possible by the expertise and dedication of:

- **Ken Webster** - Creator of [MuonFP](https://github.com/sundruid/muonfp), the TCP fingerprinting methodology that forms the foundation of this project
- **Vlad Iliushin** - Creator of the eBPF based firewall implementation that showcases MuonFP in action

[Contribute](CONTRIBUTING.md) to this research project and help advance TCP fingerprinting technology!

## Licensing

This software is dual-licensed under:
- [GNU Affero General Public License v3.0](https://www.gnu.org/licenses/agpl-3.0.en.html) - For open-source use
- Proprietary license - For commercial use without AGPLv3 requirements (reach out to info@ellio.tech for more information)

---

<p align="center">
  <em>Demonstrating the power of TCP fingerprinting for proactive security.</em><br>
  <strong>Recon Shield: Advancing network defense through TCP fingerprinting research.</strong>
</p>
