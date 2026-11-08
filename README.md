# NETIPV6

IPv6 packets, interfaces, addresses and routes.

NETIPV6 owns the bounded IPv6 interface, address, route, receive and reassembly
state. The existing NIC/Ethernet path supplies copied frames and actual TX
acknowledgements. ICMPv6 checksums and neighbor state remain in the declared
net.icmpv6 and net.ndp dependencies; no IPv6 stack is added to the Kernel.

An interface requires an up Ethernet link, acknowledged multicast reception,
a real monotonic clock and the existing entropy provider. Link generation,
provider identity and clock identity bind timed work. Missing prerequisites
report zero capabilities; a genuine link-local DAD conflict keeps the
interface unusable until its actual link epoch changes.

The initial policy provides MAC-derived link-local addresses, Enhanced DAD,
manual additional addresses and /64 SLAAC. Preferred/valid lifetimes, prefix
and router state remain distinct. There is no DHCPv6, forwarding, privacy
address, SEND or redirect-route policy. Packet transmission is bounded to
1280 IPv6 bytes; PMTU discovery is not advertised. Receive reassembly admits
16 datagrams, at least1500 total IPv6 bytes each, with a60-second deadline.
Overlap poisons the whole datagram; fragmented ND is rejected.

Copied upper-layer queues preserve complete records and validate TCP/UDP
pseudoheaders. This packet facility does not advertise working TCP, UDP or
DNS endpoints; those owners qualify their own IPv6 capabilities separately.

Build with `Build.sh` on Linux or `Build.bat` on Windows; `test` runs the
bounded component cases. `module.R4MF` owns module version, imports, profile,
dependencies and image placement. The pinned SDK selects the platform contract.

Normative contract: `Repositories/Contract/API/Ipv6Providers.txt` in the R4OS
workspace. `DOCUMENTATION.de.txt` records the provider boundary. Host codec,
controlled guest/peer and physical NIC/IRQ/DMA qualifications are separate.
Existing applications keep their current imports and operation.
