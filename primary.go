package sam3

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/eyedeekay/sam3/i2pkeys"
)

const (
	session_ADDOK = "SESSION STATUS RESULT=OK"
)

func randport() string {
	s := rand.NewSource(time.Now().UnixNano())
	r := rand.New(s)
	p := r.Intn(55534) + 10000
	return strconv.Itoa(p)
}

// Represents a primary session.
type PrimarySession struct {
	samAddr  string          // address to the sam bridge (ipv4:port)
	id       string          // tunnel name
	conn     net.Conn        // connection to sam
	keys     i2pkeys.I2PKeys // i2p destination keys
	Timeout  time.Duration
	Deadline time.Time
	sigType  string
	Config   SAMEmit
	stsess   *StreamSession
	dgsess   *DatagramSession
	//	from     string
	//	to       string
}

func (ss *PrimarySession) From() string {
	return "0"
}

func (ss *PrimarySession) To() string {
	return "0"
}

func (ss *PrimarySession) SignatureType() string {
	return ss.sigType
}

// Returns the local tunnel name of the I2P tunnel used for the stream session
func (ss *PrimarySession) ID() string {
	return ss.id
}

func (ss *PrimarySession) Close() error {
	return ss.conn.Close()
}

// Returns the I2P destination (the address) of the stream session
func (ss *PrimarySession) Addr() i2pkeys.I2PAddr {
	//	fmt.Println("LOCAL ADDR")
	return ss.keys.Addr()
}

func (ss *PrimarySession) LocalAddr() net.Addr {
	//	fmt.Println("LOCAL ADDR")
	aa := ss.keys.Addr()
	return &aa
}

// Returns the keys associated with the stream session
func (ss *PrimarySession) Keys() i2pkeys.I2PKeys {
	return ss.keys
}

func (sam *PrimarySession) Dial(network, addr string) (net.Conn, error) {
	if network == "udp" || network == "udp4" || network == "udp6" {
		return sam.DialUDPI2P(network, network+addr[0:4], addr)
	}
	if network == "tcp" || network == "tcp4" || network == "tcp6" {
		return sam.DialTCPI2P(network, network+addr[0:4], addr)
	}
	return nil, fmt.Errorf("Error: Must specify a valid network type")
}

// DialTCP implements x/dialer
func (sam *PrimarySession) DialTCP(network string, laddr, raddr net.Addr) (net.Conn, error) {
	var err error
	if sam.stsess == nil {
		sam.stsess, err = sam.NewUniqueStreamSubSession(network + RandString())
		if err != nil {
			return nil, err
		}
	}
	return sam.stsess.Dial(network, raddr.String())
}

func (sam *PrimarySession) DialTCPI2P(network string, laddr, raddr string) (*SAMConn, error) {
	var err error
	if sam.stsess == nil {
		sam.stsess, err = sam.NewUniqueStreamSubSession(network + RandString())
		if err != nil {
			return nil, err
		}
	}
	c, err := sam.stsess.Dial(network, raddr)
	if err != nil {
		return nil, err
	}
	return c.(*SAMConn), nil
}

// DialUDP implements x/dialer
func (sam *PrimarySession) DialUDP(network string, laddr, raddr net.Addr) (net.PacketConn, error) {
	var err error
	if sam.dgsess == nil {
		sam.dgsess, err = sam.NewDatagramSubSession(network+raddr.String()[0:4], 0)
		if err != nil {
			return nil, err
		}
	}
	return sam.dgsess.Dial(network, raddr.String())
}

func (sam *PrimarySession) DialUDPI2P(network, laddr, raddr string) (*DatagramSession, error) {
	var err error
	if sam.dgsess == nil {
		sam.dgsess, err = sam.NewDatagramSubSession(network+raddr[0:4], 0)
		if err != nil {
			return nil, err
		}
	}
	return sam.dgsess.Dial(network, raddr)
}

func (s *PrimarySession) Lookup(name string) (a net.Addr, err error) {
	var sam *SAM
	if len(strings.Split(name, ":")) <= 1 {
		name += ":80"
	}
	sam, err = NewSAM(s.samAddr)
	if err == nil {
		defer sam.Close()
		a, err = sam.Lookup(name)
	}
	return
}

func (sam *PrimarySession) Resolve(network, addr string) (net.Addr, error) {
	fmt.Println("LOGGING RESOLUTION", network, addr)
	return sam.Lookup(addr)
}

func (sam *PrimarySession) ResolveTCPAddr(network, dest string) (net.Addr, error) {
	fmt.Println("LOGGING RESOLUTION", network, dest)
	return sam.Lookup(dest)
}

func (sam *PrimarySession) ResolveUDPAddr(network, dest string) (net.Addr, error) {
	fmt.Println("LOGGING RESOLUTION", network, dest)
	return sam.Lookup(dest)
}

// Creates a new PrimarySession with the I2CP- and streaminglib options as
// specified. See the I2P documentation for a full list of options.
func (sam *SAM) NewPrimarySession(id string, keys i2pkeys.I2PKeys, options []string) (*PrimarySession, error) {
	conn, err := sam.newGenericSession("PRIMARY", id, keys, options, []string{})
	if err != nil {
		return nil, err
	}
	return &PrimarySession{sam.Config.I2PConfig.Sam(), id, conn, keys, time.Duration(600 * time.Second), time.Now(), Sig_NONE, sam.Config, nil, nil}, nil
}

// Creates a new PrimarySession with the I2CP- and PRIMARYinglib options as
// specified. See the I2P documentation for a full list of options.
func (sam *SAM) NewPrimarySessionWithSignature(id string, keys i2pkeys.I2PKeys, options []string, sigType string) (*PrimarySession, error) {
	conn, err := sam.newGenericSessionWithSignature("PRIMARY", id, keys, sigType, options, []string{})
	if err != nil {
		return nil, err
	}
	return &PrimarySession{sam.Config.I2PConfig.Sam(), id, conn, keys, time.Duration(600 * time.Second), time.Now(), sigType, sam.Config, nil, nil}, nil
}

// Creates a new session with the style of either "STREAM", "DATAGRAM" or "RAW",
// for a new I2P tunnel with name id, using the cypher keys specified, with the
// I2CP/streaminglib-options as specified. Extra arguments can be specified by
// setting extra to something else than []string{}.
// This sam3 instance is now a session
func (sam *PrimarySession) newGenericSubSession(style, id string, extras []string) (net.Conn, error) {
	return sam.newGenericSubSessionWithSignature(style, id, extras)
}

func (sam *PrimarySession) newGenericSubSessionWithSignature(style, id string, extras []string) (net.Conn, error) {
	return sam.newGenericSubSessionWithSignatureAndPorts(style, id, "0", "0", extras)
}

// Creates a new session with the style of either "STREAM", "DATAGRAM" or "RAW",
// for a new I2P tunnel with name id, using the cypher keys specified, with the
// I2CP/streaminglib-options as specified. Extra arguments can be specified by
// setting extra to something else than []string{}.
// This sam3 instance is now a session
func (sam *PrimarySession) newGenericSubSessionWithSignatureAndPorts(style, id, from, to string, extras []string) (net.Conn, error) {

	conn := sam.conn
	fp := ""
	tp := ""
	if from != "0" {
		fp = " FROM_PORT=" + from
	}
	if to != "0" {
		tp = " TO_PORT=" + to
	}
	scmsg := []byte("SESSION ADD STYLE=" + style + fp + tp + " ID=" + id + " " + strings.Join(extras, " ") + "\n")
	for m, i := 0, 0; m != len(scmsg); i++ {
		if i == 15 {
			conn.Close()
			return nil, errors.New("writing to SAM failed")
		}
		n, err := conn.Write(scmsg[m:])
		if err != nil {
			conn.Close()
			return nil, err
		}
		m += n
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return nil, err
	}
	text := string(buf[:n])
	if strings.HasPrefix(text, session_ADDOK) {
		//if sam.keys.String() != text[len(session_ADDOK):len(text)-1] {
		//conn.Close()
		//return nil, errors.New("SAMv3 created a tunnel with keys other than the ones we asked it for")
		//}
		return conn, nil //&StreamSession{id, conn, keys, nil, sync.RWMutex{}, nil}, nil
	} else if text == session_DUPLICATE_ID {
		conn.Close()
		return nil, errors.New("Duplicate tunnel name")
	} else if text == session_DUPLICATE_DEST {
		conn.Close()
		return nil, errors.New("Duplicate destination")
	} else if text == session_INVALID_KEY {
		conn.Close()
		return nil, errors.New("Invalid key")
	} else if strings.HasPrefix(text, session_I2P_ERROR) {
		conn.Close()
		return nil, errors.New("I2P error " + text[len(session_I2P_ERROR):])
	} else {
		conn.Close()
		return nil, errors.New("Unable to parse SAMv3 reply: " + text)
	}
}

// Creates a new StreamSession with the I2CP- and streaminglib options as
// specified. See the I2P documentation for a full list of options.
func (sam *PrimarySession) NewStreamSubSession(id string) (*StreamSession, error) {
	s := RandString()
	conn, err := sam.newGenericSubSession("STREAM", id+s, []string{})
	if err != nil {
		return nil, err
	}
	return &StreamSession{sam.Config.I2PConfig.Sam(), id + s, conn, sam.keys, time.Duration(600 * time.Second), time.Now(), Sig_NONE, "0", "0"}, nil
}

// Creates a new StreamSession with the I2CP- and streaminglib options as
// specified. See the I2P documentation for a full list of options.
func (sam *PrimarySession) NewUniqueStreamSubSession(id string) (*StreamSession, error) {
	s := RandString()
	conn, err := sam.newGenericSubSession("STREAM", id+s, []string{})
	if err != nil {
		return nil, err
	}
	return &StreamSession{sam.Config.I2PConfig.Sam(), id + s, conn, sam.keys, time.Duration(600 * time.Second), time.Now(), Sig_NONE, randport(), "0"}, nil
}

// Creates a new StreamSession with the I2CP- and streaminglib options as
// specified. See the I2P documentation for a full list of options.
func (sam *PrimarySession) NewStreamSubSessionWithPorts(id, from, to string) (*StreamSession, error) {
	conn, err := sam.newGenericSubSessionWithSignatureAndPorts("STREAM", id, from, to, []string{})
	if err != nil {
		return nil, err
	}
	return &StreamSession{sam.Config.I2PConfig.Sam(), id, conn, sam.keys, time.Duration(600 * time.Second), time.Now(), Sig_NONE, from, to}, nil
}

/*
func (s *PrimarySession) I2PListener(name string) (*StreamListener, error) {
	listener, err := s.NewStreamSubSession(name)
	if err != nil {
		return nil, err
	}
	return listener.Listen()
}
*/

// Creates a new datagram session. udpPort is the UDP port SAM is listening on,
// and if you set it to zero, it will use SAMs standard UDP port.
func (s *PrimarySession) NewDatagramSubSession(id string, udpPort int) (*DatagramSession, error) {
	if udpPort > 65335 || udpPort < 0 {
		return nil, errors.New("udpPort needs to be in the intervall 0-65335")
	}
	if udpPort == 0 {
		udpPort = 7655
	}
	lhost, _, err := net.SplitHostPort(s.conn.LocalAddr().String())
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
	rhost, _, err := net.SplitHostPort(s.conn.RemoteAddr().String())
	if err != nil {
		s.Close()
		return nil, err
	}
	rUDPAddr, err := net.ResolveUDPAddr("udp4", rhost+":"+strconv.Itoa(udpPort))
	if err != nil {
		return nil, err
	}
	_, lport, err := net.SplitHostPort(udpconn.LocalAddr().String())
	conn, err := s.newGenericSubSession("DATAGRAM", id, []string{"PORT=" + lport})
	if err != nil {
		return nil, err
	}
	return &DatagramSession{s.Config.I2PConfig.Sam(), id, conn, udpconn, s.keys, rUDPAddr, nil}, nil
}

// Creates a new raw session. udpPort is the UDP port SAM is listening on,
// and if you set it to zero, it will use SAMs standard UDP port.
func (s *PrimarySession) NewRawSubSession(id string, udpPort int) (*RawSession, error) {
	if udpPort > 65335 || udpPort < 0 {
		return nil, errors.New("udpPort needs to be in the intervall 0-65335")
	}
	if udpPort == 0 {
		udpPort = 7655
	}
	lhost, _, err := net.SplitHostPort(s.conn.LocalAddr().String())
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
	rhost, _, err := net.SplitHostPort(s.conn.RemoteAddr().String())
	if err != nil {
		s.Close()
		return nil, err
	}
	rUDPAddr, err := net.ResolveUDPAddr("udp4", rhost+":"+strconv.Itoa(udpPort))
	if err != nil {
		return nil, err
	}
	_, lport, err := net.SplitHostPort(udpconn.LocalAddr().String())
	//	conn, err := s.newGenericSubSession("RAW", id, s.keys, options, []string{"PORT=" + lport})
	conn, err := s.newGenericSubSession("RAW", id, []string{"PORT=" + lport})
	if err != nil {
		return nil, err
	}
	return &RawSession{s.Config.I2PConfig.Sam(), id, conn, udpconn, s.keys, rUDPAddr}, nil
}
