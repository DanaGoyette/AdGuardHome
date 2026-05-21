package dnsforward

import (
	"net"
	"strings"

	"github.com/miekg/dns"
)

const EDNS_MAC_RAW_CODE = 65001
const EDNS_MAC_TEXT_CODE = 65073

// ednsMACFromMsg extracts a MAC address from a custom EDNS0 local option in the
// request message. It supports raw MAC bytes in option code 65001 and Text MAC
// strings in option code 65073.
func ednsMACFromMsg(req *dns.Msg) (mac net.HardwareAddr, ok bool) {

	if req == nil {
		return nil, false
	}

	opt := req.IsEdns0()
	if opt == nil {
		return nil, false
	}

	for _, e := range opt.Option {
		option, optionOk := e.(*dns.EDNS0_LOCAL)
		if !optionOk {
			continue
		}
		switch option.Code {
		case EDNS_MAC_RAW_CODE:
			return parseRawMAC(option.Data)
		case EDNS_MAC_TEXT_CODE:
			return parseTextMAC(option.Data)
		}
	}

	return nil, false
}

func parseRawMAC(data []byte) (mac net.HardwareAddr, ok bool) {
	switch len(data) {
	case 6, 8, 20:
		macAddr := net.HardwareAddr(data)
		if macAddr != nil {
			return macAddr, true
		}
	}
	return nil, false
}

func parseTextMAC(data []byte) (mac net.HardwareAddr, ok bool) {
	if len(data) == 0 {
		return nil, false
	}

	str := strings.TrimSpace(string(data))
	macAddr, err := net.ParseMAC(str)
	if err != nil {
		return nil, false
	}

	return macAddr, true
}

// Add an OPT RR, making sure there's only one.
// (It's not clear whether multiple calls to setEdns0() will result in multiple OPT records.)
func getOrAddOptRecord(msg *dns.Msg) (opt *dns.OPT) {
	opt = msg.IsEdns0()
	if opt == nil {
		msg.SetEdns0(4096, false)
		opt = msg.IsEdns0()
	}
	return opt
}

// addRawMACToMsg adds a raw MAC address to the DNS message as an EDNS0_LOCAL option; this is only for testing
func addRawMACToMsg(msg *dns.Msg, mac net.HardwareAddr) {
	if msg == nil || len(mac) != 6 {
		return
	}

	opt := getOrAddOptRecord(msg)
	opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{
		Code: EDNS_MAC_RAW_CODE,
		Data: mac,
	})
}

// addTextMACToMsg adds a Text MAC address to the DNS message as an EDNS0_LOCAL option; this is only for testing
func addTextMACToMsg(msg *dns.Msg, mac net.HardwareAddr) {
	if msg == nil || len(mac) == 0 {
		return
	}

	opt := getOrAddOptRecord(msg)
	opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{
		Code: EDNS_MAC_TEXT_CODE,
		Data: []byte(mac.String()),
	})
}
