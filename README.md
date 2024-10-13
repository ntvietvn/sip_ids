A lightweight SIP intrusion detection system that scans SIP port scan and authentication tentative:

* Based on very basic rules, it detects potential risks and add the source IP (attackers' IPs) to iptables DROP
* In the same time it sends back to the attacker application an SIP ACK to stop it using spoofing IP (src IP replaced by one of another attacker)

Potential improvements: It was developed in one day so a lot to improve

* Using BPF to improve perf istead of using libpcap
* Daemonize it
* String parsing
* etc
