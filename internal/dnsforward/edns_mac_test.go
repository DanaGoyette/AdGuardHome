package dnsforward

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestEdnsMACFromMsg_RawMAC(t *testing.T) {
	req := createTestMessageWithType("example.com.", dns.TypeA)
	req.SetEdns0(4096, false)
	opt := req.IsEdns0()
	opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{Code: 65001, Data: net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}})

	mac, ok := ednsMACFromMsg(req)
	assert.True(t, ok)
	assert.Equal(t, net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}, mac)
}

func TestEdnsMACFromMsg_TextMAC(t *testing.T) {
	req := createTestMessageWithType("example.com.", dns.TypeA)
	req.SetEdns0(4096, false)
	opt := req.IsEdns0()
	opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{Code: EDNS_MAC_TEXT_CODE, Data: []byte("11:22:33:44:55:66")})

	mac, ok := ednsMACFromMsg(req)
	assert.True(t, ok)
	assert.Equal(t, net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}, mac)
}

func TestEdnsMACFromMsg_invalidMAC(t *testing.T) {
	req := createTestMessageWithType("example.com.", dns.TypeA)
	req.SetEdns0(4096, false)
	opt := req.IsEdns0()
	opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{Code: EDNS_MAC_RAW_CODE, Data: []byte{1, 2, 3}})

	mac, ok := ednsMACFromMsg(req)
	assert.False(t, ok)
	assert.Equal(t, nil, mac)
}

func TestAddRawMACToMsg(t *testing.T) {
	req := createTestMessageWithType("example.com.", dns.TypeA)
	mac := net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	addRawMACToMsg(req, mac)

	opt := req.IsEdns0()
	if opt == nil {
		t.Errorf("Expected EDNS0 option to be present")
	}

	foundOpt := (*dns.EDNS0_LOCAL)(nil)
	for _, e := range opt.Option {
		opt, optOk := e.(*dns.EDNS0_LOCAL)
		if optOk && opt.Code == EDNS_MAC_RAW_CODE {
			foundOpt = opt
			break
		}
	}

	if foundOpt == nil {
		t.Errorf("Expected to find raw MAC option with value %v", mac)
	}
	assert.Equal(t, mac, net.HardwareAddr(foundOpt.Data))
}

func TestAddTextMACToMsg(t *testing.T) {
	req := createTestMessageWithType("example.com.", dns.TypeA)
	mac := net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	addTextMACToMsg(req, mac)

	opt := req.IsEdns0()
	if opt == nil {
		t.Errorf("Expected EDNS0 option to be present")
	}

	foundOpt := (*dns.EDNS0_LOCAL)(nil)
	for _, e := range opt.Option {
		opt, optOk := e.(*dns.EDNS0_LOCAL)
		if optOk && opt.Code == EDNS_MAC_TEXT_CODE {
			foundOpt = opt
			break
		}
	}

	if foundOpt == nil {
		t.Errorf("Expected to find Text MAC option with value %v", mac)
	}
	assert.Equal(t, mac, net.HardwareAddr(foundOpt.Data))
}
