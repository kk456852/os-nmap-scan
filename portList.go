package main

type portlist_proto int

const (
	PORTLIST_PROTO_TCP  portlist_proto = 0
	PORTLIST_PROTO_UDP  portlist_proto = 1
	PORTLIST_PROTO_SCTP portlist_proto = 2
	PORTLIST_PROTO_IP   portlist_proto = 3
	PORTLIST_PROTO_MAX  portlist_proto = 4
)

const (
	PORT_HIGHEST_STATE = 9
)

type PortList struct {
	numscriptresults   int
	idstr              string
	state_counts_proto [PORTLIST_PROTO_MAX][PORT_HIGHEST_STATE]int
}
