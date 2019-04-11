package sam3

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
)

import (
	. "github.com/eyedeekay/sam3/i2pkeys"
)

type SAMResolver struct {
	*SAM
}

func NewSAMResolver(parent *SAM) (*SAMResolver, error) {
	var s SAMResolver
	s.SAM = parent
	return &s, nil
}

func NewFullSAMResolver(address string) (*SAMResolver, error) {
	var s SAMResolver
	var err error
	s.SAM, err = NewSAM(address)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// Performs a lookup, probably this order: 1) routers known addresses, cached
// addresses, 3) by asking peers in the I2P network.
func (sam *SAMResolver) Resolve(name string) (I2PAddr, error) {
	if _, err := sam.Conn.Write([]byte("NAMING LOOKUP NAME=" + name + "\n")); err != nil {
		sam.Close()
		return I2PAddr(""), err
	}
	buf := make([]byte, 4096)
	n, err := sam.Conn.Read(buf)
	if err != nil {
		sam.Close()
		return I2PAddr(""), err
	}
	if n <= 13 || !strings.HasPrefix(string(buf[:n]), "NAMING REPLY ") {
		return I2PAddr(""), errors.New("Failed to parse.")
	}
	s := bufio.NewScanner(bytes.NewReader(buf[13:n]))
	s.Split(bufio.ScanWords)

	errStr := ""
	for s.Scan() {
		text := s.Text()
		if text == "RESULT=OK" {
			continue
		} else if text == "RESULT=INVALID_KEY" {
			errStr += "Invalid key."
		} else if text == "RESULT=KEY_NOT_FOUND" {
			errStr += "Unable to resolve " + name
		} else if text == "NAME="+name {
			continue
		} else if strings.HasPrefix(text, "VALUE=") {
			return I2PAddr(text[6:]), nil
		} else if strings.HasPrefix(text, "MESSAGE=") {
			errStr += " " + text[8:]
		} else {
			continue
		}
	}
	return I2PAddr(""), errors.New(errStr)
}
