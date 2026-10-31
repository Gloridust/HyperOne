// Package socks provides a minimal SOCKS5 server for the HyperOne client's
// local listener, plus the address encoding HyperOne reuses as the first
// message on an inner stream (the target the server should dial).
package socks

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// SOCKS5 address types (RFC 1928).
const (
	atypIPv4   byte = 0x01
	atypDomain byte = 0x03
	atypIPv6   byte = 0x04
)

// ErrBadAddr is returned for a malformed address encoding.
var ErrBadAddr = errors.New("socks: malformed address")

// Addr is a destination the server will dial: a host (IP or domain) and port.
type Addr struct {
	Host string
	Port int
}

func (a Addr) String() string { return net.JoinHostPort(a.Host, strconv.Itoa(a.Port)) }

// ReadAddr decodes one SOCKS5 address (atyp + addr + 2-byte port) from r.
func ReadAddr(r io.Reader) (Addr, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return Addr{}, err
	}
	var host string
	switch atyp[0] {
	case atypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return Addr{}, err
		}
		host = net.IP(b).String()
	case atypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return Addr{}, err
		}
		host = net.IP(b).String()
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return Addr{}, err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return Addr{}, err
		}
		host = string(b)
	default:
		return Addr{}, ErrBadAddr
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return Addr{}, err
	}
	return Addr{Host: host, Port: int(p[0])<<8 | int(p[1])}, nil
}

// Encode serializes a as atyp + addr + 2-byte port. A host that parses as an
// IP uses the IPv4/IPv6 form; anything else is sent as a domain name so the
// server resolves it (keeping DNS off the censored network).
func (a Addr) Encode() ([]byte, error) {
	var out []byte
	if ip := net.ParseIP(a.Host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, atypIPv4)
			out = append(out, v4...)
		} else {
			out = append(out, atypIPv6)
			out = append(out, ip.To16()...)
		}
	} else {
		if len(a.Host) > 255 {
			return nil, fmt.Errorf("socks: host too long")
		}
		out = append(out, atypDomain, byte(len(a.Host)))
		out = append(out, a.Host...)
	}
	if a.Port < 0 || a.Port > 0xffff {
		return nil, fmt.Errorf("socks: bad port %d", a.Port)
	}
	out = append(out, byte(a.Port>>8), byte(a.Port))
	return out, nil
}
