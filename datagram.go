package sam3

import (
	"bytes"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/eyedeekay/i2pkeys"
)

// The DatagramSession implements net.PacketConn. It works almost like ordinary
// UDP, except that datagrams may be at most 31kB large. These datagrams are
// also end-to-end encrypted, signed and includes replay-protection. And they
// are also built to be surveillance-resistant (yey!).
type DatagramSession struct {
	samAddr    string           // address to the sam bridge (ipv4:port)
	id         string           // tunnel name
	conn       net.Conn         // connection to sam bridge
	udpconn    *net.UDPConn     // used to deliver datagrams
	keys       i2pkeys.I2PKeys  // i2p destination keys
	rUDPAddr   *net.UDPAddr     // the SAM bridge UDP-port
	remoteAddr *i2pkeys.I2PAddr // optional remote I2P address
}

// Creates a new datagram session. udpPort is the UDP port SAM is listening on,
// and if you set it to zero, it will use SAMs standard UDP port.
func (s *SAM) NewDatagramSession(id string, keys i2pkeys.I2PKeys, options []string, udpPort int) (*DatagramSession, error) {
	if udpPort > 65335 || udpPort < 0 {
		return nil, errors.New("udpPort needs to be in the intervall 0-65335")
	}
	if udpPort == 0 {
		udpPort = 7655
	}
	lhost, _, err := SplitHostPort(s.conn.LocalAddr().String())
	if err != nil {
		s.Close()
		return nil, err
	}
	lUDPAddr, err := net.ResolveUDPAddr("udp4", lhost+":0")
	if err != nil {
		return nil, err
	}
	udpconn, err := net.ListenUDP("udp4", lUDPAddr)
	if err != nil {
		return nil, err
	}
	rhost, _, err := SplitHostPort(s.conn.RemoteAddr().String())
	if err != nil {
		s.Close()
		return nil, err
	}
	rUDPAddr, err := net.ResolveUDPAddr("udp4", rhost+":"+strconv.Itoa(udpPort))
	if err != nil {
		return nil, err
	}
	_, lport, err := net.SplitHostPort(udpconn.LocalAddr().String())
	if err != nil {
		s.Close()
		return nil, err
	}
	conn, err := s.newGenericSession("DATAGRAM", id, keys, options, []string{" PORT=" + lport})
	if err != nil {
		return nil, err
	}
	return &DatagramSession{s.address, id, conn, udpconn, keys, rUDPAddr, nil}, nil
}

func (s *DatagramSession) B32() string {
	return s.keys.Addr().Base32()
}

func (s *DatagramSession) Dial(net string, addr string) (*DatagramSession, error) {
	netaddr, err := s.Lookup(addr)
	if err != nil {
		return nil, err
	}
	return s.DialI2PRemote(net, netaddr)
}

func (s *DatagramSession) DialRemote(net, addr string) (net.PacketConn, error) {
	netaddr, err := s.Lookup(addr)
	if err != nil {
		return nil, err
	}
	return s.DialI2PRemote(net, netaddr)
}

func (s *DatagramSession) DialI2PRemote(net string, addr net.Addr) (*DatagramSession, error) {
	switch addr.(type) {
	case *i2pkeys.I2PAddr:
		s.remoteAddr = addr.(*i2pkeys.I2PAddr)
	case i2pkeys.I2PAddr:
		i2paddr := addr.(i2pkeys.I2PAddr)
		s.remoteAddr = &i2paddr
	}
	return s, nil
}

func (s *DatagramSession) RemoteAddr() net.Addr {
	return s.remoteAddr
}

// Reads one datagram sent to the destination of the DatagramSession. Returns
// the number of bytes read, from what address it was sent, or an error.
// implements net.PacketConn
func (s *DatagramSession) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	// extra bytes to read the remote address of incomming datagram
	buf := make([]byte, len(b)+4096)

	for {
		// very basic protection: only accept incomming UDP messages from the IP of the SAM bridge
		var saddr *net.UDPAddr
		n, saddr, err = s.udpconn.ReadFromUDP(buf)
		if err != nil {
			return 0, i2pkeys.I2PAddr(""), err
		}
		if bytes.Equal(saddr.IP, s.rUDPAddr.IP) {
			continue
		}
		break
	}
	i := bytes.IndexByte(buf, byte('\n'))
	if i > 4096 || i > n {
		return 0, i2pkeys.I2PAddr(""), errors.New("Could not parse incomming message remote address.")
	}
	raddr, err := i2pkeys.NewI2PAddrFromString(string(buf[:i]))
	if err != nil {
		return 0, i2pkeys.I2PAddr(""), errors.New("Could not parse incomming message remote address: " + err.Error())
	}
	// shift out the incomming address to contain only the data received
	if (n - i + 1) > len(b) {
		copy(b, buf[i+1:i+1+len(b)])
		return n - (i + 1), raddr, errors.New("Datagram did not fit into your buffer.")
	} else {
		copy(b, buf[i+1:n])
		return n - (i + 1), raddr, nil
	}
}

func (s *DatagramSession) Accept() (net.Conn, error) {
	return s, nil
}

func (s *DatagramSession) Read(b []byte) (n int, err error) {
	rint, _, rerr := s.ReadFrom(b)
	return rint, rerr
}

// Sends one signed datagram to the destination specified. At the time of
// writing, maximum size is 31 kilobyte, but this may change in the future.
// Implements net.PacketConn.
func (s *DatagramSession) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	header := []byte("3.1 " + s.id + " " + addr.String() + "\n")
	msg := append(header, b...)
	n, err = s.udpconn.WriteToUDP(msg, s.rUDPAddr)
	return n, err
}

func (s *DatagramSession) Write(b []byte) (int, error) {
	return s.WriteTo(b, s.remoteAddr)
}

// Closes the DatagramSession. Implements net.PacketConn
func (s *DatagramSession) Close() error {
	err := s.conn.Close()
	err2 := s.udpconn.Close()
	if err != nil {
		return err
	}
	return err2
}

// Returns the I2P destination of the DatagramSession.
func (s *DatagramSession) LocalI2PAddr() i2pkeys.I2PAddr {
	return s.keys.Addr()
}

// Implements net.PacketConn
func (s *DatagramSession) LocalAddr() net.Addr {
	return s.LocalI2PAddr()
}

func (s *DatagramSession) Addr() net.Addr {
	return s.LocalI2PAddr()
}

func (s *DatagramSession) Lookup(name string) (a net.Addr, err error) {
	var sam *SAM
	sam, err = NewSAM(s.samAddr)
	if err == nil {
		defer sam.Close()
		a, err = sam.Lookup(name)
	}
	return
}

// Sets read and write deadlines for the DatagramSession. Implements
// net.PacketConn and does the same thing. Setting write deadlines for datagrams
// is seldom done.
func (s *DatagramSession) SetDeadline(t time.Time) error {
	return s.udpconn.SetDeadline(t)
}

// Sets read deadline for the DatagramSession. Implements net.PacketConn
func (s *DatagramSession) SetReadDeadline(t time.Time) error {
	return s.udpconn.SetReadDeadline(t)
}

// Sets the write deadline for the DatagramSession. Implements net.Packetconn.
func (s *DatagramSession) SetWriteDeadline(t time.Time) error {
	return s.udpconn.SetWriteDeadline(t)
}

func (s *DatagramSession) SetWriteBuffer(bytes int) error {
	return s.udpconn.SetWriteBuffer(bytes)
}
