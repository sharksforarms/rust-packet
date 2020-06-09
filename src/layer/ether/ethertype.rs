use deku::prelude::*;

// Inspired from https://github.com/secdev/scapy/blob/master/scapy/libs/ethertypes.py

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(id_type = "u16", endian = "big")]
pub enum EtherType {
    /// IEEE 802.3 packet
    #[deku(id = "0x0004")]
    IEEE8023,
    /// Xerox PUP protocol - see 0A00
    #[deku(id = "0x0200")]
    PUP,
    /// PUP Address Translation - see 0A01
    #[deku(id = "0x0200")]
    PUPAT,
    /// XNS
    #[deku(id = "0x0600")]
    NS,
    /// XNS Address Translation (3Mb only)
    #[deku(id = "0x0601")]
    NSAT,
    /// DLOG (?)
    #[deku(id = "0x0660")]
    DLOG1,
    /// DLOG (?)
    #[deku(id = "0x0661")]
    DLOG2,
    /// IP protocol
    #[deku(id = "0x0800")]
    IPv4,
    /// X.75 Internet
    #[deku(id = "0x0801")]
    X75,
    /// NBS Internet
    #[deku(id = "0x0802")]
    NBS,
    /// ECMA Internet
    #[deku(id = "0x0803")]
    ECMA,
    /// CHAOSnet
    #[deku(id = "0x0804")]
    CHAOS,
    /// X.25 Level 3
    #[deku(id = "0x0805")]
    X25,
    /// Address resolution protocol
    #[deku(id = "0x0806")]
    ARP,
    /// Frame Relay ARP (RFC1701)
    #[deku(id = "0x0808")]
    FRARP,
    /// Banyan VINES
    #[deku(id = "0x0bad")]
    VINES,
    /// Trailer packet
    #[deku(id = "0x1000")]
    TRAIL,
    /// DCA - Multicast
    #[deku(id = "0x1234")]
    DCA,
    /// VALID system protocol
    #[deku(id = "0x1600")]
    VALID,
    /// Datapoint Corporation (RCL lan protocol)
    #[deku(id = "0x1995")]
    RCL,
    /// 3Com NBP Connect complete not registered
    #[deku(id = "0x3c04")]
    NBPCC,
    /// 3Com NBP Datagram (like XNS IDP) not registered
    #[deku(id = "0x3c07")]
    NBPDG,
    /// PCS Basic Block Protocol
    #[deku(id = "0x4242")]
    PCS,
    /// Information Modes Little Big LAN
    #[deku(id = "0x4c42")]
    IMLBL,
    /// DEC MOP dump/load
    #[deku(id = "0x6001")]
    MOPDL,
    /// DEC MOP remote console
    #[deku(id = "0x6002")]
    MOPRC,
    /// DEC LAT
    #[deku(id = "0x6004")]
    LAT,
    /// DEC LAVC, SCA
    #[deku(id = "0x6007")]
    SCA,
    /// DEC AMBER
    #[deku(id = "0x6008")]
    AMBER,
    /// Raw Frame Relay (RFC1701)
    #[deku(id = "0x6559")]
    RAWFR,
    /// Ungermann-Bass download
    #[deku(id = "0x7000")]
    UBDL,
    /// Ungermann-Bass NIUs
    #[deku(id = "0x7001")]
    UBNIU,
    /// Ungermann-Bass ??? (NMC to/from UB Bridge)
    #[deku(id = "0x7003")]
    UBNMC,
    /// Ungermann-Bass Bridge Spanning Tree
    #[deku(id = "0x7005")]
    UBBST,
    /// OS/9 Microware
    #[deku(id = "0x7007")]
    OS9,
    /// Racal-Interlan
    #[deku(id = "0x7030")]
    RACAL,
    /// HP Probe
    #[deku(id = "0x8005")]
    HP,
    /// Tigan, Inc.
    #[deku(id = "0x802f")]
    TIGAN,
    /// DEC Availability Manager for Distributed Systems DECamds (but someone at DEC says not)
    #[deku(id = "0x8048")]
    DECAM,
    /// Stanford V Kernel exp.
    #[deku(id = "0x805b")]
    VEXP,
    /// Stanford V Kernel prod.
    #[deku(id = "0x805c")]
    VPROD,
    /// Evans & Sutherland
    #[deku(id = "0x805d")]
    ES,
    /// Veeco Integrated Auto.
    #[deku(id = "0x8067")]
    VEECO,
    /// AT&T
    #[deku(id = "0x8069")]
    ATT,
    /// Matra
    #[deku(id = "0x807a")]
    MATRA,
    /// Dansk Data Elektronik
    #[deku(id = "0x807b")]
    DDE,
    /// Merit Internodal (or Univ of Michigan?)
    #[deku(id = "0x807c")]
    MERIT,
    /// AppleTalk
    #[deku(id = "0x809b")]
    ATALK,
    /// Pacer Software
    #[deku(id = "0x80c6")]
    PACER,
    /// IBM SNA Services over Ethernet
    #[deku(id = "0x80d5")]
    SNA,
    /// Retix
    #[deku(id = "0x80f2")]
    RETIX,
    /// AppleTalk AARP
    #[deku(id = "0x80f3")]
    AARP,
    /// IEEE 802.1Q VLAN tagging (XXX conflicts)
    #[deku(id = "0x8100")]
    VLAN,
    /// Wellfleet; BOFL (Breath OF Life) pkts [every 5-10 secs.]
    #[deku(id = "0x8102")]
    BOFL,
    /// Hayes Microcomputers (XXX which?)
    #[deku(id = "0x8130")]
    HAYES,
    /// VG Laboratory Systems
    #[deku(id = "0x8131")]
    VGLAB,
    /// Novell (old) NetWare IPX (ECONFIG E option)
    #[deku(id = "0x8137")]
    IPX,
    /// M/MUMPS data sharing
    #[deku(id = "0x813f")]
    MUMPS,
    /// Vrije Universiteit (NL) FLIP (Fast Local Internet Protocol)
    #[deku(id = "0x8146")]
    FLIP,
    /// Network Computing Devices
    #[deku(id = "0x8149")]
    NCD,
    /// Alpha Micro
    #[deku(id = "0x814a")]
    ALPHA,
    /// SNMP over Ethernet (see RFC1089)
    #[deku(id = "0x814c")]
    SNMP,
    /// Protocol Engines XTP
    #[deku(id = "0x817d")]
    XTP,
    /// SGI/Time Warner prop.
    #[deku(id = "0x817e")]
    SGITW,
    /// Scheduled Transfer STP, HIPPI-ST
    #[deku(id = "0x8181")]
    STP,
    /// IP protocol version 6
    #[deku(id = "0x86dd")]
    IPv6,
    /// Control Technology Inc. RDP Without IP
    #[deku(id = "0x8739")]
    RDP,
    /// Control Technology Inc. Mcast Industrial Ctrl Proto.
    #[deku(id = "0x873a")]
    MICP,
    /// IP Autonomous Systems (RFC1701)
    #[deku(id = "0x876c")]
    IPAS,
    /// 803.3ad slow protocols (LACP/Marker)
    #[deku(id = "0x8809")]
    SLOW,
    /// PPP (obsolete by PPPOE)
    #[deku(id = "0x880b")]
    PPP,
    /// MPLS Unicast
    #[deku(id = "0x8847")]
    MPLS,
    /// Axis Communications AB proprietary bootstrap/config
    #[deku(id = "0x8856")]
    AXIS,
    /// PPP Over Ethernet Session Stage
    #[deku(id = "0x8864")]
    PPPOE,
    /// 802.1X Port Access Entity
    #[deku(id = "0x888e")]
    PAE,
    /// ATA over Ethernet
    #[deku(id = "0x88a2")]
    AOE,
    /// 802.1ad VLAN stacking
    #[deku(id = "0x88a8")]
    QINQ,
    /// Link Layer Discovery Protocol
    #[deku(id = "0x88cc")]
    LLDP,
    /// 802.1Q Provider Backbone Bridging
    #[deku(id = "0x88e7")]
    PBB,
    /// 3Com (Formerly Bridge Communications), XNS Systems Management
    #[deku(id = "0x9001")]
    XNSSM,
    /// 3Com (Formerly Bridge Communications), TCP/IP Systems Management
    #[deku(id = "0x9002")]
    TCPSM,
    /// DECNET? Used by VAX 6220 DEBNI
    #[deku(id = "0xaaaa")]
    DEBNI,
    /// Sonix Arpeggio
    #[deku(id = "0xfaf5")]
    SONIX,
    /// BBN VITAL-LanBridge cache wakeups
    #[deku(id = "0xff00")]
    VITAL,
    /// Maximum valid ethernet type, reserved
    #[deku(id = "0xffff")]
    MAX,
}
