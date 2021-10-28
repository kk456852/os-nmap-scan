package main

import (
	"math"
	"math/rand"
	"net"
	"time"
	"github.com/spf13/viper"
	"github.com/google/gopacket/pcap"
)

const NUM_SEQ_SAMPLES = 6
const NUM_FPTESTS = 13
const MAX_FP_RESULTS = 36

const (
	OP_FAILURE = -1
	OP_SUCCESS = 0
)


type OFProbeType uint32

const (
	OFP_UNSET OFProbeType = 1 << (32 - 1 - iota)
	OFP_TSEQ
	OFP_TOPS
	OFP_TECN
	OFP_T1_7
	OFP_TICMP
	OFP_TUDP
)

type dist_calc_method uint32

const (
	DIST_METHOD_NONE dist_calc_method = 1 << (32 - 1 - iota)
	DIST_METHOD_LOCALHOST
	DIST_METHOD_DIRECT
	DIST_METHOD_ICMP
	DIST_METHOD_TRACEROUTE
)

var c *Config
var perf scan_performance_vars

type Config struct {
	NmapOs     NmapOs
}

type NmapOs struct {
	min_parallelism int
	max_parallelism int
	db_path         string
	host_timeout    uint64
}

type scan_performance_vars struct {
	low_cwnd int
	host_initial_cwnd int
	group_initial_cwnd int
	max_cwnd int
	slow_incr int
	ca_incr int
	cc_scale_max int
	initial_ssthresh int
	group_drop_cwnd_divisor float64
	group_drop_ssthresh_divisor float64
	host_drop_ssthresh_divisor float64
}

func (s *scan_performance_vars) init(){
	var maxOpInt int
	if c.NmapOs.min_parallelism != 0 {
		s.low_cwnd = c.NmapOs.min_parallelism
	}else {
		s.low_cwnd = 1
	}
	if c.NmapOs.max_parallelism != 0 {
		maxOpInt = c.NmapOs.max_parallelism
	}else {
		maxOpInt = 300
	}
	if s.max_cwnd > maxOpInt{
		s.max_cwnd = maxOpInt
	}
}

func os_scan_ipv4(Targets []*Target) int {
	var itry int
	var unMatchedHosts []*HostOsScanInfo
	perf.init()
	OSI, err := newOsScanInfo(Targets)
	if err != nil  || len(Targets) == 0 || OSI.numIncompleteHosts() == 0{
		return OP_FAILURE
	}
	OSI.starttime =
}

type HostOsScanInfo struct {
	target *Target
	FPR    *FingerPrintResultsIPv4
	OSI    *OsScanInfo
}

type OsScanInfo struct {
	starttime         float64
	numInitialTargets uint32
	incompleteHosts   []*HostOsScanInfo
}

func (i *OsScanInfo) numIncompleteHosts() int {
	return len(i.incompleteHosts)
}

type FingerPrintResultsIPv4 struct {
	numFPs int
}

type state_reason_t struct {
	reason_id uint16
	ttl       uint16
}


type FingerPrintResults struct {
	num_perfect_matches         int
	num_matches                 int
	overall_results             int
	osscan_opentcpport          int
	osscan_closedtcpport        int
	osscan_closedudpport        int
	distance                    int
	distance_guess              int
	distance_calculation_method dist_calc_method
	maxTimingRatio              float64
	incomplete                  bool
	isClassified                bool
	OSR                         OS_Classification_Results
}

type OS_Classification_Results struct {
	OSC                     *[MAX_FP_RESULTS]OS_Classification
	OSC_Accuracy            [MAX_FP_RESULTS]float64
	OSC_num_perfect_matches int
	OSC_num_matches         int
	overall_results         int
}

type ScanStats struct {
	num_probes_active            int
	num_probes_send              int
	num_probes_sent_at_last_wait int
}

type HostOsScanStats struct {
	si                                        seq_info
	ipid                                      ipid_info
	distance                                  int
	distance_guess                            int
	openTCPPort, closedTCPPort, closedUDPPort int
	probesToSend                              []*OFProbe
	probesActive                              []*OFProbe
	num_probes_sent                           uint
	sendDelayMs                               uint
	lastProbeSent                             time.Time
	timing                                    ultra_timing_vals
	FP                                        *FingerPrint
	FPtests                                   [NUM_FPTESTS]*FingerTest
	TOps_AVs                                  [6]*AVal
	TWin_AVs                                  [6]*AVal
	lastipid                                  uint16
	seq_send_times                            [NUM_SEQ_SAMPLES]time.Time
	TWinReplyNum                              int
	TOpsReplyNum                              int
	storedIcmpReply                           int
	upi                                       udpprobeinfo
}

func newOsScanInfo(targets []*Target) (*OsScanInfo, error) {
	OSI :=  &OsScanInfo{}
	var targetno uint16
	var hsi *HostOsScanInfo
	num_timedout := 0
	OSI.numInitialTargets = 0
	for i:=0; i<len(targets);i++ {
		if targets[i].timedOut(time.Now()){
			num_timedout++
			continue
		}
	}
	OSI.nextTarget =
	return OSI, nil
}

func (s *HostOsScanStats) addNewProbe(probeType OFProbeType, i int) {
	var probe *OFProbe
	probe.type_ = probeType
	probe.subid = i
	s.probesToSend = append(s.probesToSend, probe)
}

func (s *HostOsScanStats) removeActiveProbe(probeI *OFProbeType) {

}

type FingerPrint struct {
	match FingerMatch
	tests []FingerTest
}

type FingerTest struct {
	name string
}

type AVal struct {
	attribute string
	value     string
}

type FingerMatch struct {
	line      int
	numprints uint16
	OS_name   string
	OS_class  []OS_Classification
}

type OS_Classification struct {
	OS_Vendor     string
	OS_Family     string
	OS_Generation string
	Device_Type   string
	cpe           []string
}

type ultra_timing_vals struct {
	cwnd                 float64
	ssthresh             int
	num_replies_expected int
	num_replies_received int
	num_updates          int
	last_drop            time.Time
}

type OFProbe struct {
	subid         int
	tryno         int
	type_         OFProbeType
	retransmitted bool
	sent          time.Time
	prevSent      time.Time
}

type nrand_handle struct {
	i, j   uint8
	s      [256]uint8
	tmp    *uint8
	tmplen int
}

type HostOsScan struct {
	pacap_t     *pcap.Handle
	stats       *ScanStats
	rawsd       int
	ethsd       net.Interface
	tcpSeqBase  uint32
	tcpAck      uint32
	tcpMss      int
	udpttl      int
	icmpEchoId  uint16
	icmpEchoSeq uint16
	tcpPortBase int
	udpPortBase int
}

type seq_info struct {
	responses       int
	ts_seqclasses   int
	ipid_seqclasses int
	seqs            [NUM_SEQ_SAMPLES]int
	timestamps      [NUM_SEQ_SAMPLES]int
	index           int
	ipids           [NUM_SEQ_SAMPLES]int
	lastboot        time.Time
}

type ipid_info struct {
	tcp_ipids        [NUM_SEQ_SAMPLES]uint32
	tcp_closed_ipids [NUM_SEQ_SAMPLES]uint32
	icmp_ipids       [NUM_SEQ_SAMPLES]uint32
}

type udpprobeinfo struct {
	iptl        uint16
	ipid        uint16
	ipck        uint16
	sport       uint16
	dport       uint16
	udpck       uint16
	udplen      uint16
	patternbyte uint8
	target      in_addr
}

type in_addr_t uint32

type in_addr struct {
	s_addr in_addr_t
}

func (h *HostOsScan) reInitScanSystem() {
	h.tcpSeqBase = get_random_u32()
	h.tcpAck = get_random_u32()
	h.tcpMss = 265
	h.icmpEchoId = get_random_u16()
	h.icmpEchoSeq = 295
	h.udpttl = randIntRange(51, 69)
}

func (h *HostOsScan) buildSeqProbeList(hss *HostOsScanStats) {
	if hss == nil {
		return
	}
	var i int
	if hss.openTCPPort == -1 {
		return
	}
	if hss.FPtests[0] == nil {
		return
	}
	for i = 0; i < NUM_SEQ_SAMPLES; i++ {
		hss.addNewProbe(OFP_TSEQ, i)
	}

}

func get_random_u16() uint16 {
	return uint16(randIntRange(0, math.MaxUint16))
}

func randIntRange(min, max int) int {
	if min == max {
		return min
	}
	return rand.Intn((max+1)-min) + min
}

func get_random_u32() uint32 {
	var a = rand.Uint32()
	return a
}

func main() {
	v := viper.New()
	v.SetConfigFile("./config.yaml")
	v.SetConfigType("yaml")
	if err1 := v.ReadInConfig(); err1 != nil {
		return
	}
	c.NmapOs.max_parallelism = v.GetInt("NmapOs.max_parallelism")
	c.NmapOs.min_parallelism = v.GetInt("NmapOS.min_parallelism")
	c.NmapOs.db_path         = v.GetString("NmapOS.db_path")


}

func getTargetOsFingerPrint(target net.IPAddr) string {
	return ""
}

func matchFingerPrintDB(fingerPrint string) string {
	return ""
}
