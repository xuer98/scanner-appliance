package engine

// rawSocketsAllowed is false on Windows: the daemon-only host build runs
// nmap, if present, in connect mode without OS detection (Npcap and an
// elevated prompt are the operator's business, not the daemon's).
func rawSocketsAllowed() bool { return false }
