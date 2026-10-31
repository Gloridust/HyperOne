package socks

import (
	"fmt"
	"io"
	"net"
)

// SOCKS5 constants.
const (
	version5    byte = 0x05
	cmdConnect  byte = 0x01
	authNone    byte = 0x00
	repSuccess  byte = 0x00
	repGenFail  byte = 0x01
	repCmdNotSup byte = 0x07
)

// Handshake performs the SOCKS5 greeting and CONNECT request on c, returning
// the requested destination. It replies with success before returning; the
// caller then pipes bytes between c and the tunnel. Only no-auth CONNECT is
// supported, which is all a local loopback proxy needs.
func Handshake(c net.Conn) (Addr, error) {
	// Greeting: version, nmethods, methods...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return Addr{}, err
	}
	if hdr[0] != version5 {
		return Addr{}, fmt.Errorf("socks: unsupported version 0x%02x", hdr[0])
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return Addr{}, err
	}
	if _, err := c.Write([]byte{version5, authNone}); err != nil {
		return Addr{}, err
	}

	// Request: version, cmd, rsv, atyp, addr, port
	req := make([]byte, 3)
	if _, err := io.ReadFull(c, req); err != nil {
		return Addr{}, err
	}
	if req[0] != version5 {
		return Addr{}, fmt.Errorf("socks: bad request version 0x%02x", req[0])
	}
	if req[1] != cmdConnect {
		reply(c, repCmdNotSup)
		return Addr{}, fmt.Errorf("socks: unsupported command 0x%02x", req[1])
	}
	addr, err := ReadAddr(c)
	if err != nil {
		reply(c, repGenFail)
		return Addr{}, err
	}
	if err := reply(c, repSuccess); err != nil {
		return Addr{}, err
	}
	return addr, nil
}

// reply sends a minimal SOCKS5 reply with a zero BND.ADDR (0.0.0.0:0), which
// clients accept for CONNECT.
func reply(c net.Conn, code byte) error {
	_, err := c.Write([]byte{version5, code, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}
