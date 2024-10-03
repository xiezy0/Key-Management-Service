package message

type TypeOfMessage int

const (
	ABA_ALL TypeOfMessage = iota + 1
	ABA_BVAL
	ABA_AUX
	ABA_CONF
	ABA_FINAL
	HACSS_ALL
	HACSS_SEND
	HACSS_ECHO
	HACSS_READY
	HACSS_RECONSTRUCT
)

type ProtocolType int

const (
	RBC   ProtocolType = 1
	ABA   ProtocolType = 2
	ECRBC ProtocolType = 3
	CBC   ProtocolType = 4
	EVCBC ProtocolType = 5
	MVBA  ProtocolType = 6
	HACSS ProtocolType = 7
)

type VCBCType int

const (
	DEFAULT_HASH VCBCType = 0
	MERKLE       VCBCType = 1
)
