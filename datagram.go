package sam3

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/go-i2p/i2pkeys"
	"github.com/go-i2p/sam3/common"
)

// The DatagramSession implements net.PacketConn. It works almost like ordinary
// UDP, except that datagrams may be at most 31kB large. These datagrams are
// also end-to-end encrypted, signed and includes replay-protection. And they
// are also built to be surveillance-resistant (yey!).
type DatagramSession struct {
	samAddr    string           // address to the sam bridge (ipv4:port)
	id         string           // tunnel name
	conn       net.Conn         // connection to sam bridge
	keys       i2pkeys.I2PKeys  // i2p destination keys
	remoteAddr *i2pkeys.I2PAddr // optional remote I2P address
	common.UDPSession
	*DatagramOptions
}

// Creates a new datagram session. udpPort is the UDP port SAM is listening on,
// and if you set it to zero, it will use SAMs standard UDP port.
func (s *SAM) NewDatagramSession(id string, keys i2pkeys.I2PKeys, options []string, udpPort int, datagramOptions ...DatagramOptions) (*DatagramSession, error) {
	log.WithFields(logrus.Fields{
		"id":      id,
		"udpPort": udpPort,
	}).Debug("Creating new DatagramSession")
	udpSessionConfig := &common.UDPSessionConfig{
		Port:          udpPort,
		ParentConn:    s.conn,
		Log:           log,
		DefaultPort:   7655,
		AllowZeroPort: true,
		// Add required session parameters
		Style:        "DATAGRAM",
		FromPort:     "0", // Allow dynamic port assignment
		ToPort:       "0",
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	udpconn, err := common.NewUDPSession(udpSessionConfig)
	if err != nil {
		log.WithError(err).Error("Failed to create UDP session")
		return nil, err
	}
	_, lport, err := net.SplitHostPort(udpconn.Conn.LocalAddr().String())
	if err != nil {
		log.WithError(err).Error("Failed to get local port")
		s.Close()
		return nil, err
	}
	conn, err := s.newGenericSession("DATAGRAM", id, keys, options, []string{" PORT=" + lport})
	if err != nil {
		log.WithError(err).Error("Failed to create generic session")
		return nil, err
	}
	if len(datagramOptions) > 0 {
		return &DatagramSession{
			samAddr:         s.address,
			id:              id,
			conn:            conn,
			keys:            keys,
			UDPSession:      *udpconn,
			DatagramOptions: &datagramOptions[0],
		}, nil
	}
	log.WithField("id", id).Info("DatagramSession created successfully")
	//	return &DatagramSession{s.address, id, conn, udpconn, keys, rUDPAddr, nil, nil}, nil
	return &DatagramSession{
		samAddr:    s.address,
		id:         id,
		conn:       conn,
		keys:       keys,
		UDPSession: *udpconn,
	}, nil
}

func (s *DatagramSession) B32() string {
	b32 := s.keys.Addr().Base32()
	log.WithField("b32", b32).Debug("Generated B32 address")
	return b32
}

func (s *DatagramSession) Dial(net, addr string) (*DatagramSession, error) {
	log.WithFields(logrus.Fields{
		"net":  net,
		"addr": addr,
	}).Debug("Dialing address")
	netaddr, err := s.Lookup(addr)
	if err != nil {
		log.WithError(err).Error("Lookup failed")
		return nil, err
	}
	return s.DialI2PRemote(net, netaddr)
}

func (s *DatagramSession) DialRemote(net, addr string) (net.PacketConn, error) {
	log.WithFields(logrus.Fields{
		"net":  net,
		"addr": addr,
	}).Debug("Dialing remote address")
	netaddr, err := s.Lookup(addr)
	if err != nil {
		log.WithError(err).Error("Lookup failed")
		return nil, err
	}
	return s.DialI2PRemote(net, netaddr)
}

func (s *DatagramSession) DialI2PRemote(net string, addr net.Addr) (*DatagramSession, error) {
	log.WithFields(logrus.Fields{
		"net":  net,
		"addr": addr,
	}).Debug("Dialing I2P remote address")
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
	log.WithField("remoteAddr", s.remoteAddr).Debug("Getting remote address")
	return s.remoteAddr
}

// Reads one datagram sent to the destination of the DatagramSession. Returns
// the number of bytes read, from what address it was sent, or an error.
// implements net.PacketConn
func (s *DatagramSession) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	log.Debug("Reading datagram")
	// Use sync.Pool for buffers
	bufPool := sync.Pool{
		New: func() interface{} {
			return make([]byte, len(b)+4096)
		},
	}
	buf := bufPool.Get().([]byte)
	defer bufPool.Put(buf)

	for {
		// very basic protection: only accept incomming UDP messages from the IP of the SAM bridge
		var saddr *net.UDPAddr
		n, saddr, err = s.UDPSession.Conn.ReadFromUDP(buf)
		if err != nil {
			log.WithError(err).Error("Failed to read from UDP")
			return 0, i2pkeys.I2PAddr(""), err
		}
		if bytes.Equal(saddr.IP, s.UDPSession.RemoteAddr.IP) {
			continue
		}
		break
	}
	i := bytes.IndexByte(buf, byte(' '))
	if i > 4096 || i > n {
		log.Error("Could not parse incoming message remote address")
		return 0, i2pkeys.I2PAddr(""), errors.New("Could not parse incomming message remote address.")
	}
	raddr, err := i2pkeys.NewI2PAddrFromString(string(buf[:i]))
	if err != nil {
		log.WithError(err).Error("Could not parse incoming message remote address")
		return 0, i2pkeys.I2PAddr(""), errors.New("Could not parse incomming message remote address: " + err.Error())
	}
	// shift out the incomming address to contain only the data received
	if (n - i + 1) > len(b) {
		copy(b, buf[i+1:i+1+len(b)])
		return n - (i + 1), raddr, errors.New("Datagram did not fit into your buffer.")
	} else {
		copy(b, buf[i+1:n])
		log.WithField("bytesRead", n-(i+1)).Debug("Datagram read successfully")
		return n - (i + 1), raddr, nil
	}
}

func (s *DatagramSession) Accept() (net.Conn, error) {
	log.Debug("Accept called on DatagramSession")
	return s, nil
}

func (s *DatagramSession) Read(b []byte) (n int, err error) {
	log.Debug("Reading from DatagramSession")
	rint, _, rerr := s.ReadFrom(b)
	return rint, rerr
}

const (
	MAX_DATAGRAM_SIZE = 31744 // Max reliable size
	RECOMMENDED_SIZE  = 11264 // 11KB recommended max
)

// Sends one signed datagram to the destination specified. At the time of
// writing, maximum size is 31 kilobyte, but this may change in the future.
// Implements net.PacketConn.
func (s *DatagramSession) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	log.WithFields(logrus.Fields{
		"addr":        addr,
		"datagramLen": len(b),
	}).Debug("Writing datagram")

	if len(b) > MAX_DATAGRAM_SIZE {
		return 0, errors.New("datagram exceeds maximum size")
	}

	// Use chunking for anything above recommended size
	if len(b) > RECOMMENDED_SIZE {
		return s.writeChunked(b, addr)
	}

	// Single message path
	if s.DatagramOptions != nil {
		return s.writeToWithOptions(b, addr.(i2pkeys.I2PAddr))
	}
	header := []byte(fmt.Sprintf("3.1 %s %s\n", s.id, addr.(i2pkeys.I2PAddr).String()))
	msg := append(header, b...)
	n, err = s.UDPSession.Conn.WriteToUDP(msg, s.UDPSession.RemoteAddr)
	if err != nil {
		log.WithError(err).Error("Failed to write to UDP")
	} else {
		log.WithField("bytesWritten", n).Debug("Datagram written successfully")
	}
	return n, err
}

func (s *DatagramSession) writeChunked(b []byte, addr net.Addr) (total int, err error) {
	chunkSize := RECOMMENDED_SIZE - 256 // Allow for header overhead
	chunks := (len(b) + chunkSize - 1) / chunkSize

	log.WithFields(logrus.Fields{
		"totalSize": len(b),
		"chunks":    chunks,
	}).Debug("Splitting datagram into chunks")

	for i := 0; i < chunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(b) {
			end = len(b)
		}

		chunk := b[start:end]
		var n int

		// Single write path that handles both cases
		if s.DatagramOptions != nil {
			n, err = s.writeToWithOptions(chunk, addr.(i2pkeys.I2PAddr))
		} else {
			header := []byte(fmt.Sprintf("3.1 %s %s %d %d\n", s.id, addr.(i2pkeys.I2PAddr).String(), i, chunks))
			msg := append(header, chunk...)
			n, err = s.UDPSession.Conn.WriteToUDP(msg, s.UDPSession.RemoteAddr)
		}

		if err != nil {
			return total, fmt.Errorf("chunk %d/%d failed: %w", i+1, chunks, err)
		}
		total += n

		if i < chunks-1 {
			time.Sleep(50 * time.Millisecond)
		}
	}

	return total, nil
}

type DatagramOptions struct {
	SendTags     int
	TagThreshold int
	Expires      int
	SendLeaseset bool
}

func (s *DatagramSession) writeToWithOptions(b []byte, addr i2pkeys.I2PAddr) (n int, err error) {
	header := []byte(fmt.Sprintf("3.3 %s %s", s.id, addr.String()))
	if s.DatagramOptions != nil {
		if s.DatagramOptions.SendTags > 0 {
			header = append(header, []byte(fmt.Sprintf(" SEND_TAGS=%d", s.DatagramOptions.SendTags))...)
		}
		if s.DatagramOptions.TagThreshold > 0 {
			header = append(header, []byte(fmt.Sprintf(" TAG_THRESHOLD=%d", s.DatagramOptions.TagThreshold))...)
		}
		if s.DatagramOptions.Expires > 0 {
			header = append(header, []byte(fmt.Sprintf(" EXPIRES=%d", s.DatagramOptions.Expires))...)
		}
		if s.DatagramOptions.SendLeaseset {
			header = append(header, []byte(" SEND_LEASESET=true")...)
		}
	}
	header = append(header, '\n')
	msg := append(header, b...)
	return s.UDPSession.Conn.WriteToUDP(msg, s.UDPSession.RemoteAddr)
}

func (s *DatagramSession) Write(b []byte) (int, error) {
	log.WithField("dataLen", len(b)).Debug("Writing to DatagramSession")
	return s.WriteTo(b, s.remoteAddr)
}

// Closes the DatagramSession. Implements net.PacketConn
func (s *DatagramSession) Close() error {
	log.Debug("Closing DatagramSession")
	err := s.conn.Close()
	err2 := s.UDPSession.Conn.Close()
	if err != nil {
		log.WithError(err).Error("Failed to close connection")
		return err
	}
	if err2 != nil {
		log.WithError(err2).Error("Failed to close UDP connection")
	}
	return err2
}

// Returns the I2P destination of the DatagramSession.
func (s *DatagramSession) LocalI2PAddr() i2pkeys.I2PAddr {
	addr := s.keys.Addr()
	log.WithField("localI2PAddr", addr).Debug("Getting local I2P address")
	return addr
}

// Implements net.PacketConn
func (s *DatagramSession) LocalAddr() net.Addr {
	return s.LocalI2PAddr()
}

func (s *DatagramSession) Addr() net.Addr {
	return s.LocalI2PAddr()
}

func (s *DatagramSession) Lookup(name string) (a net.Addr, err error) {
	log.WithField("name", name).Debug("Looking up address")
	var sam *SAM
	sam, err = NewSAM(s.samAddr)
	if err == nil {
		defer sam.Close()
		a, err = sam.Lookup(name)
	}
	log.WithField("address", a).Debug("Lookup successful")
	return
}

// Sets read and write deadlines for the DatagramSession. Implements
// net.PacketConn and does the same thing. Setting write deadlines for datagrams
// is seldom done.
func (s *DatagramSession) SetDeadline(t time.Time) error {
	log.WithField("deadline", t).Debug("Setting deadline")
	return s.UDPSession.Conn.SetDeadline(t)
}

// Sets read deadline for the DatagramSession. Implements net.PacketConn
func (s *DatagramSession) SetReadDeadline(t time.Time) error {
	log.WithField("readDeadline", t).Debug("Setting read deadline")
	return s.UDPSession.Conn.SetReadDeadline(t)
}

// Sets the write deadline for the DatagramSession. Implements net.Packetconn.
func (s *DatagramSession) SetWriteDeadline(t time.Time) error {
	log.WithField("writeDeadline", t).Debug("Setting write deadline")
	return s.UDPSession.Conn.SetWriteDeadline(t)
}

func (s *DatagramSession) SetWriteBuffer(bytes int) error {
	log.WithField("bytes", bytes).Debug("Setting write buffer")
	return s.UDPSession.Conn.SetWriteBuffer(bytes)
}
