# ADR 0002 — Temporary accepted lab network risk (public summary)

_The full record describes the owner's home network and is kept private._

**Summary.** The lab VMs communicate only over a VirtualBox **host-only** network. During
early development each VM also had a second adapter for internet access (package updates);
the risk of that adapter was explicitly accepted for a limited time, and the adapter is kept
disconnected (or switched to NAT) unless updates are being installed. Scope files, the SSH
tunnel and the Runner use only host-only addresses. Before the host joins any untrusted
network, both VMs must be isolated first.
