package tun

import (
	"encoding/binary"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
)

type judgeLoopHandler struct {
	Handler
	judged  atomic.Int32
	release chan struct{}
}

func (h *judgeLoopHandler) JudgeFlow(uint8, netip.AddrPort, netip.AddrPort, []byte) FlowVerdict {
	h.judged.Add(1)
	<-h.release
	return FlowVerdict{}
}

type discardWriteback struct{}

func (discardWriteback) ReturnHeadroom() int               { return 0 }
func (discardWriteback) WriteReturnPackets([][]byte) error { return nil }

func testTCPSegment(flags header.TCPFlags) []byte {
	packet := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
	packet[8] = 64
	packet[9] = uint8(header.TCPProtocolNumber)
	copy(packet[12:], []byte{192, 168, 1, 10})
	copy(packet[16:], []byte{1, 2, 3, 4})
	binary.BigEndian.PutUint16(packet[20:], 40000)
	binary.BigEndian.PutUint16(packet[22:], 443)
	packet[32] = 5 << 4
	packet[33] = uint8(flags)
	return packet
}

// A non-SYN segment arriving while its flow is being judged must not be held:
// it used to drop the accept entry on resume and send the SYN back to judging.
func TestForwardStageJudgesAcceptedTCPFlowOnce(t *testing.T) {
	handler := &judgeLoopHandler{release: make(chan struct{})}
	dispatcher := NewForwardDispatcher(handler, discardWriteback{}, nil, UDPNatOptions{}, 0)
	defer dispatcher.Close()
	resumed := make(chan struct{}, 1)
	stage := dispatcher.NewStage(nil, func() {
		select {
		case resumed <- struct{}{}:
		default:
		}
	})
	if !stage.Dispatch(testTCPSegment(header.TCPFlagSyn)) {
		t.Fatal("SYN was not held for judging")
	}
	if stage.Dispatch(testTCPSegment(header.TCPFlagAck)) {
		t.Fatal("non-SYN segment was held behind a pending judgement")
	}
	close(handler.release)
	var passed int
	for quiet := false; !quiet; {
		select {
		case <-resumed:
			stage.ResumeJudged(func(packet []byte, _ ForwardFrameMeta) {
				if !stage.Dispatch(packet) {
					passed++
				}
			})
		case <-time.After(200 * time.Millisecond):
			quiet = true
		}
		if judged := handler.judged.Load(); judged > 1 {
			t.Fatalf("flow judged %d times", judged)
		}
	}
	if passed != 1 {
		t.Fatalf("%d packets reached the stack, want the SYN", passed)
	}
}
