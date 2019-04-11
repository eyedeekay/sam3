package sam3

import (
	"bytes"
	"errors"
	"net"
	"strconv"
	"time"
)

import (
	. "github.com/eyedeekay/sam3/i2pkeys"
)

// The RawSession provides no authentication of senders, and there is no sender
// address attached to datagrams, so all communication is anonymous. The
// messages send are however still endpoint-to-endpoint encrypted. You
// need to figure out a way to identify and authenticate clients yourself, iff
// that is needed. Raw datagrams may be at most 32 kB in size. There is no
// overhead of authentication, which is the reason to use this..
type RawSession struct {
	samAddr  string       // address to the sam bridge (ipv4:port)
	id       string       // tunnel name
	conn     net.Conn     // connection to sam bridge
	udpconn  *net.UDPConn // used to deliver datagrams
	keys     I2PKeys      // i2p destination keys
	rUDPAddr *net.UDPAddr // the SAM bridge UDP-port
}

// Creates a new raw session. udpPort is the UDP port SAM is listening on,
// and if you set it to zero, it will use SAMs standard UDP port.
func (s *SAM) NewRawSession(id string, keys I2PKeys, options []string, udpPort int) (*RawSession, error) {
	if udpPort > 65335 || udpPort < 0 {
		return nil, errors.New("udpPort needs to be in the intervall 0-65335")
	}
	if udpPort == 0 {
		udpPort = 7655
	}
	lhost, _, err := net.SplitHostPort(s.Conn.LocalAddr().String())
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
	rhost, _, err := net.SplitHostPort(s.Conn.RemoteAddr().String())
	if err != nil {
		s.Close()
		return nil, err
	}
	rUDPAddr, err := net.ResolveUDPAddr("udp4", rhost+":"+strconv.Itoa(udpPort))
	if err != nil {
		return nil, err
	}
	_, lport, err := net.SplitHostPort(udpconn.LocalAddr().String())
	conn, err := s.newGenericSession("RAW", id, keys, options, []string{"PORT=" + lport})
	if err != nil {
		return nil, err
	}
	return &RawSession{s.Config.I2PConfig.Sam(), id, conn, udpconn, keys, rUDPAddr}, nil
}

// Reads one raw datagram sent to the destination of the DatagramSession. Returns
// the number of bytes read. Who sent the raw message can not be determined at
// this layer - you need to do it (in a secure way!).
func (s *RawSession) Read(b []byte) (n int, err error) {
	for {
		// very basic protection: only accept incomming UDP messages from the IP of the SAM bridge
		var saddr *net.UDPAddr
		n, saddr, err = s.udpconn.ReadFromUDP(b)
		if err != nil {
			return 0, err
		}
		if bytes.Equal(saddr.IP, s.rUDPAddr.IP) {
			continue
		}
		break
	}
	return n, nil
}

// Sends one raw datagram to the destination specified. At the time of writing,
// maximum size is 32 kilobyte, but this may change in the future.
func (s *RawSession) WriteTo(b []byte, addr I2PAddr) (n int, err error) {
	header := []byte("3.0 " + s.id + " " + addr.String() + "\n")
	msg := append(header, b...)
	n, err = s.udpconn.WriteToUDP(msg, s.rUDPAddr)
	return n, err
}

// Closes the RawSession.
func (s *RawSession) Close() error {
	err := s.conn.Close()
	err2 := s.udpconn.Close()
	if err != nil {
		return err
	}
	return err2
}

// Returns the local I2P destination of the RawSession.
func (s *RawSession) LocalAddr() I2PAddr {
	return s.keys.Addr()
}

func (s *RawSession) SetDeadline(t time.Time) error {
	return s.udpconn.SetDeadline(t)
}

func (s *RawSession) SetReadDeadline(t time.Time) error {
	return s.udpconn.SetReadDeadline(t)
}

func (s *RawSession) SetWriteDeadline(t time.Time) error {
	return s.udpconn.SetWriteDeadline(t)
}
