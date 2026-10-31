package relay

import "net"

// prefixConn is a net.Conn whose reads first drain a fixed prefix of bytes that
// were already read from the socket, then continue from the socket itself.
// HyperOne uses it to replay the handoff record into the frame layer so the
// inner AEAD counter starts at zero on the exact bytes the client sent.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (p *prefixConn) Read(b []byte) (int, error) {
	if len(p.prefix) > 0 {
		n := copy(b, p.prefix)
		p.prefix = p.prefix[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}
