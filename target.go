package main

import "time"

type Target struct {
	seq                         seq_info
	distance                    int
	distance_calculation_method dist_calc_method
	FPR                         FingerPrintResults
	reason                      state_reason_t
}

var htn host_timeout_nfo

type host_timeout_nfo struct {
	msecs_used           uint64
	toclock_running      bool
	toclock_start        time.Time
	host_start, host_end time.Time
}

func (t *Target) timedOut(now time.Time) bool {
	used := htn.msecs_used
	var tv time.Time
	if c.NmapOs.host_timeout == 0 {
		return false
	}
	if htn.toclock_running {
		tv = time.Now()
		used = used + uint64(tv.Sub(htn.toclock_start).Milliseconds())
	}
	return used > c.NmapOs.host_timeout
}
