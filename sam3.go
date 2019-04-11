// Library for I2Ps SAMv3 bridge (https://geti2p.com)
package sam3

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"strings"
)

import (
	. "github.com/eyedeekay/ramp/emit"
	. "github.com/eyedeekay/sam3/i2pkeys"
)

// Used for controlling I2Ps SAMv3.
type SAM struct {
	//address  string
	Conn     net.Conn
	Resolver *SAMResolver
	Config   SAMEmit
}

const (
	session_OK             = "SESSION STATUS RESULT=OK DESTINATION="
	session_DUPLICATE_ID   = "SESSION STATUS RESULT=DUPLICATED_ID\n"
	session_DUPLICATE_DEST = "SESSION STATUS RESULT=DUPLICATED_DEST\n"
	session_INVALID_KEY    = "SESSION STATUS RESULT=INVALID_KEY\n"
	session_I2P_ERROR      = "SESSION STATUS RESULT=I2P_ERROR MESSAGE="
)

const (
	Sig_NONE                 = ""
	Sig_DSA_SHA1             = "SIGNATURE_TYPE=DSA_SHA1"
	Sig_ECDSA_SHA256_P256    = "SIGNATURE_TYPE=ECDSA_SHA256_P256"
	Sig_ECDSA_SHA384_P384    = "SIGNATURE_TYPE=ECDSA_SHA384_P384"
	Sig_ECDSA_SHA512_P521    = "SIGNATURE_TYPE=ECDSA_SHA512_P521"
	Sig_EdDSA_SHA512_Ed25519 = "SIGNATURE_TYPE=EdDSA_SHA512_Ed25519"
)

// Creates a new controller for the I2P routers SAM bridge.
func NewSAM(address string) (*SAM, error) {
	var s SAM
	// TODO: clean this up
    s.Config.I2PConfig.SetSAMAddress(address)
	conn, err := net.Dial("tcp", s.Config.I2PConfig.Sam())
	if err != nil {
		return nil, err
	}
    if _, err := conn.Write(s.Config.HelloBytes()); err != nil {
		conn.Close()
		return nil, err
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if strings.Contains(string(buf[:n]), "HELLO REPLY RESULT=OK") {
		s.Conn = conn
		s.Config.I2PConfig.DestinationKeys = nil
		s.Resolver, err = NewSAMResolver(&s)
		if err != nil {
			return nil, err
		}
		return &s, nil
		//return &SAM{address, conn, nil, nil}, nil
	} else if string(buf[:n]) == "HELLO REPLY RESULT=NOVERSION\n" {
		conn.Close()
		return nil, errors.New("That SAM bridge does not support SAMv3.")
	} else {
		conn.Close()
		return nil, errors.New(string(buf[:n]))
	}
}

func (sam *SAM) Keys() (k *I2PKeys) {
	//TODO: copy them?
	k = sam.Config.I2PConfig.DestinationKeys
	return
}

// read public/private keys from an io.Reader
func (sam *SAM) ReadKeys(r io.Reader) (err error) {
	var keys I2PKeys
	keys, err = LoadKeysIncompat(r)
	if err == nil {
		sam.Config.I2PConfig.DestinationKeys = &keys
	}
	return
}

// if keyfile fname does not exist
func (sam *SAM) EnsureKeyfile(fname string) (keys I2PKeys, err error) {
	if fname == "" {
		// transient
		keys, err = sam.NewKeys()
		if err == nil {
			sam.Config.I2PConfig.DestinationKeys = &keys
		}
	} else {
		// persistant
		_, err = os.Stat(fname)
		if os.IsNotExist(err) {
			// make the keys
			keys, err = sam.NewKeys()
			if err == nil {
				sam.Config.I2PConfig.DestinationKeys = &keys
				// save keys
				var f io.WriteCloser
				f, err = os.OpenFile(fname, os.O_WRONLY|os.O_CREATE, 0600)
				if err == nil {
					err = StoreKeysIncompat(keys, f)
					f.Close()
				}
			}
		} else if err == nil {
			// we haz key file
			var f *os.File
			f, err = os.Open(fname)
			if err == nil {
				keys, err = LoadKeysIncompat(f)
				if err == nil {
					sam.Config.I2PConfig.DestinationKeys = &keys
				}
			}
		}
	}
	return
}

// Creates the I2P-equivalent of an IP address, that is unique and only the one
// who has the private keys can send messages from. The public keys are the I2P
// desination (the address) that anyone can send messages to.
func (sam *SAM) NewKeys(sigType ...string) (I2PKeys, error) {
	sigtmp := ""
	if len(sigType) > 0 {
		sigtmp = sigType[0]
	}
	if _, err := sam.Conn.Write([]byte("DEST GENERATE " + sigtmp + "\n")); err != nil {
		return I2PKeys{}, err
	}
	buf := make([]byte, 8192)
	n, err := sam.Conn.Read(buf)
	if err != nil {
		return I2PKeys{}, err
	}
	s := bufio.NewScanner(bytes.NewReader(buf[:n]))
	s.Split(bufio.ScanWords)

	var pub, priv string
	for s.Scan() {
		text := s.Text()
		if text == "DEST" {
			continue
		} else if text == "REPLY" {
			continue
		} else if strings.HasPrefix(text, "PUB=") {
			pub = text[4:]
		} else if strings.HasPrefix(text, "PRIV=") {
			priv = text[5:]
		} else {
			return I2PKeys{}, errors.New("Failed to parse keys.")
		}
	}
	return NewKeys(I2PAddr(pub), priv), nil
}

// Performs a lookup, probably this order: 1) routers known addresses, cached
// addresses, 3) by asking peers in the I2P network.
func (sam *SAM) Lookup(name string) (I2PAddr, error) {
	return sam.Resolver.Resolve(name)
}

// Creates a new session with the style of either "STREAM", "DATAGRAM" or "RAW",
// for a new I2P tunnel with name id, using the cypher keys specified, with the
// I2CP/streaminglib-options as specified. Extra arguments can be specified by
// setting extra to something else than []string{}.
// This sam3 instance is now a session
func (sam *SAM) newGenericSession(style, id string, keys I2PKeys, options []string, extras []string) (net.Conn, error) {
	return sam.newGenericSessionWithSignature(style, id, keys, Sig_NONE, options, extras)
}

func (sam *SAM) newGenericSessionWithSignature(style, id string, keys I2PKeys, sigType string, options []string, extras []string) (net.Conn, error) {
	return sam.newGenericSessionWithSignatureAndPorts(style, id, "0", "0", keys, sigType, options, extras)
}

// Creates a new session with the style of either "STREAM", "DATAGRAM" or "RAW",
// for a new I2P tunnel with name id, using the cypher keys specified, with the
// I2CP/streaminglib-options as specified. Extra arguments can be specified by
// setting extra to something else than []string{}.
// This sam3 instance is now a session
func (sam *SAM) newGenericSessionWithSignatureAndPorts(style, id, from, to string, keys I2PKeys, sigType string, options []string, extras []string) (net.Conn, error) {

	optStr := ""
	for _, opt := range options {
		optStr += opt + " "
	}

	conn := sam.Conn
	scmsg := []byte("SESSION CREATE STYLE=" + style + " FROM_PORT=" + from + " TO_PORT=" + to + " ID=" + id + " DESTINATION=" + keys.String() + " " + sigType + " " + optStr + strings.Join(extras, " ") + "\n")
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
	if strings.HasPrefix(text, session_OK) {
		if keys.String() != text[len(session_OK):len(text)-1] {
			conn.Close()
			return nil, errors.New("SAMv3 created a tunnel with keys other than the ones we asked it for")
		}
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

// close this sam session
func (sam *SAM) Close() error {
	return sam.Conn.Close()
}
