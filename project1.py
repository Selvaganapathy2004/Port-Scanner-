import nmap

nm = nmap.PortScanner()

target = "172.16.4.33"
options = "-sV -sC -oN scan_results"

nm.scan(target, arguments=options)

for host in nm.all_hosts():
    print("Host: %s (%s)" % (host, nm[host].hostname()))
    print("State: %s" % nm[host].state())
    for protocol in nm[host].all_protocols():
        print("Protocol: %s" % protocol)
        port_info = nm[host][protocol]
        for port, state in port_info.items():
            print("Port: %s \tState: %s" % (port, state))
