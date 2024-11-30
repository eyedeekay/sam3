package sam3

import (
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/go-i2p/i2pkeys"
	"github.com/go-i2p/sam3/common"
)

const DEFAULT_LEASESET_TYPE = "i2cp.leaseSetEncType=4"

type SessionOptions struct {
	Style         string
	SignatureType string
	FromPort      string
	ToPort        string
	Protocol      string
	UDPPort       int
}

// Add transport options
type TransportOptions struct {
	UseCompression string
	FastReceive    string
	Reliability    string
	IdleTimeout    time.Duration
}

// I2PConfig is a struct which manages I2P configuration options
type I2PConfig struct {
	SamHost string
	SamPort string
	TunName string

	SamMin string
	SamMax string

	SessionOptions
	TransportOptions

	DestinationKeys i2pkeys.I2PKeys

	SigType                   string
	EncryptLeaseSet           string
	LeaseSetKey               string
	LeaseSetPrivateKey        string
	LeaseSetPrivateSigningKey string
	LeaseSetKeys              i2pkeys.I2PKeys
	InAllowZeroHop            string
	OutAllowZeroHop           string
	InLength                  string
	OutLength                 string
	InQuantity                string
	OutQuantity               string
	InVariance                string
	OutVariance               string
	InBackupQuantity          string
	OutBackupQuantity         string
	CloseIdle                 string
	ReduceIdle                string
	ReduceIdleTime            string
	ReduceIdleQuantity        string
	LeaseSetEncryption        string

	// Streaming Library options
	AccessListType string
	AccessList     []string
}

// Sam returns the SAM address in the form of "host:port"
func (f *I2PConfig) Sam() string {
	host := "127.0.0.1"
	port := "7656"
	if f.SamHost != "" {
		host = f.SamHost
	}
	if f.SamPort != "" {
		port = f.SamPort
	}
	log.WithFields(logrus.Fields{
		"host": host,
		"port": port,
	}).Debug("SAM address constructed")
	return host + ":" + port
}

// SetSAMAddress sets the SAM address from a string in the form of "host:port"
func (f *I2PConfig) SetSAMAddress(addr string) {
	hp := strings.Split(addr, ":")
	if len(hp) == 1 {
		f.SamHost = hp[0]
	} else if len(hp) == 2 {
		f.SamPort = hp[1]
		f.SamHost = hp[0]
	}
	f.SamPort = "7656"
	f.SamHost = "127.0.0.1"
	log.WithFields(logrus.Fields{
		"host": f.SamHost,
		"port": f.SamPort,
	}).Debug("SAM address set")
	i2pkeys.DefaultSAMAddress = f.Sam()
}

// ID returns the tunnel name in the form of "ID=name"
func (f *I2PConfig) ID() string {
	if f.TunName == "" {
		b := make([]byte, 12)
		for i := range b {
			b[i] = "abcdefghijklmnopqrstuvwxyz"[rand.Intn(len("abcdefghijklmnopqrstuvwxyz"))]
		}
		f.TunName = string(b)
		log.WithField("TunName", f.TunName).Debug("Generated random tunnel name")
	}
	return " ID=" + f.TunName + " "
}

// Leasesetsettings returns the lease set settings in the form of "i2cp.leaseSetKey=key i2cp.leaseSetPrivateKey=key i2cp.leaseSetPrivateSigningKey=key"
func (f *I2PConfig) Leasesetsettings() (string, string, string) {
	var r, s, t string
	if f.LeaseSetKey != "" {
		r = " i2cp.leaseSetKey=" + f.LeaseSetKey + " "
	}
	if f.LeaseSetPrivateKey != "" {
		s = " i2cp.leaseSetPrivateKey=" + f.LeaseSetPrivateKey + " "
	}
	if f.LeaseSetPrivateSigningKey != "" {
		t = " i2cp.leaseSetPrivateSigningKey=" + f.LeaseSetPrivateSigningKey + " "
	}
	log.WithFields(logrus.Fields{
		"leaseSetKey":               r,
		"leaseSetPrivateKey":        s,
		"leaseSetPrivateSigningKey": t,
	}).Debug("Lease set settings constructed")
	return r, s, t
}

// FromPort returns the from port setting in the form of "FROM_PORT=port"
func (f *I2PConfig) FromPort() string {
	if f.samMax() < common.SAM31Version.Number {
		log.Debug("SAM version < 3.1, FromPort not applicable")
		return ""
	}
	if f.SessionOptions.FromPort != "0" {
		log.WithField("fromPort", f.SessionOptions.FromPort).Debug("FromPort set")
		return " FROM_PORT=" + f.SessionOptions.FromPort + " "
	}
	log.Debug("FromPort not set")
	return ""
}

// ToPort returns the to port setting in the form of "TO_PORT=port"
func (f *I2PConfig) ToPort() string {
	if f.samMax() < common.SAM31Version.Number {
		log.Debug("SAM version < 3.1, ToPort not applicable")
		return ""
	}
	if f.SessionOptions.ToPort != "0" {
		log.WithField("toPort", f.SessionOptions.ToPort).Debug("ToPort set")
		return " TO_PORT=" + f.SessionOptions.ToPort + " "
	}
	log.Debug("ToPort not set")
	return ""
}

// SessionStyle returns the session style setting in the form of "STYLE=style"
func (f *I2PConfig) SessionStyle() string {
	if f.SessionOptions.Style != "" {
		log.WithField("style", f.SessionOptions.Style).Debug("Session style set")
		return " STYLE=" + f.SessionOptions.Style + " "
	}
	log.Debug("Using default STREAM style")
	return " STYLE=STREAM "
}

func (f *I2PConfig) samMax() float64 {
	i, err := strconv.Atoi(f.SamMax)
	if err != nil {
		log.WithError(err).Warn("Failed to parse SamMax, using default 3.1")
		return 3.1
	}
	log.WithField("samMax", float64(i)).Debug("SAM max version parsed")
	return float64(i)
}

// MinSAM returns the minimum SAM version required in major.minor form
func (f *I2PConfig) MinSAM() string {
	if f.SamMin == "" {
		log.Debug("Using default MinSAM: 3.1")
		return "3.1"
	}
	log.WithField("minSAM", f.SamMin).Debug("MinSAM set")
	return f.SamMin
}

// MaxSAM returns the maximum SAM version required in major.minor form
func (f *I2PConfig) MaxSAM() string {
	if f.SamMax == "" {
		log.Debug("Using default MaxSAM: 3.3")
		return "3.3"
	}
	log.WithField("maxSAM", f.SamMax).Debug("MaxSAM set")
	return f.SamMax
}

// DestinationKey returns the destination key setting in the form of "DESTINATION=key"
func (f *I2PConfig) DestinationKey() string {
	if &f.DestinationKeys != nil {
		log.WithField("destinationKey", f.DestinationKeys.String()).Debug("Destination key set")
		return " DESTINATION=" + f.DestinationKeys.String() + " "
	}
	log.Debug("Using TRANSIENT destination")
	return " DESTINATION=TRANSIENT "
}

// SignatureType returns the signature type setting in the form of "SIGNATURE_TYPE=type"
func (f *I2PConfig) SignatureType() string {
	if f.samMax() < common.SAM31Version.Number {
		log.Debug("SAM version < 3.1, SignatureType not applicable")
		return ""
	}
	if f.SigType != "" {
		log.WithField("sigType", f.SigType).Debug("Signature type set")
		return " SIGNATURE_TYPE=" + f.SigType + " "
	}
	log.Debug("Signature type not set")
	return ""
}

// EncryptLease returns the lease set encryption setting in the form of "i2cp.encryptLeaseSet=true"
func (f *I2PConfig) EncryptLease() string {
	if f.EncryptLeaseSet == "true" {
		log.Debug("Lease set encryption enabled")
		return " i2cp.encryptLeaseSet=true "
	}
	log.Debug("Lease set encryption not enabled")
	return ""
}

// Reliability returns the message reliability setting in the form of "i2cp.messageReliability=reliability"
func (f *I2PConfig) Reliability() string {
	if f.TransportOptions.Reliability != "" {
		log.WithField("reliability", f.TransportOptions.Reliability).Debug("Message reliability set")
		return " i2cp.messageReliability=" + f.TransportOptions.Reliability + " "
	}
	log.Debug("Message reliability not set")
	return ""
}

// Reduce returns the reduce idle settings in the form of "i2cp.reduceOnIdle=true i2cp.reduceIdleTime=time i2cp.reduceQuantity=quantity"
func (f *I2PConfig) Reduce() string {
	if f.ReduceIdle == "true" {
		log.WithFields(logrus.Fields{
			"reduceIdle":         f.ReduceIdle,
			"reduceIdleTime":     f.ReduceIdleTime,
			"reduceIdleQuantity": f.ReduceIdleQuantity,
		}).Debug("Reduce idle settings applied")
		return "i2cp.reduceOnIdle=" + f.ReduceIdle + "i2cp.reduceIdleTime=" + f.ReduceIdleTime + "i2cp.reduceQuantity=" + f.ReduceIdleQuantity
	}
	log.Debug("Reduce idle settings not applied")
	return ""
}

// Close returns the close idle settings in the form of "i2cp.closeOnIdle=true i2cp.closeIdleTime=time"
func (f *I2PConfig) Close() string {
	if f.CloseIdle == "true" {
		log.WithFields(logrus.Fields{
			"closeIdle":     f.CloseIdle,
			"closeIdleTime": f.TransportOptions.IdleTimeout.String(),
		}).Debug("Close idle settings applied")
		return "i2cp.closeOnIdle=" + f.CloseIdle + "i2cp.closeIdleTime=" + f.TransportOptions.IdleTimeout.String()
	}
	log.Debug("Close idle settings not applied")
	return ""
}

// DoZero returns the zero hop settings in the form of "inbound.allowZeroHop=true outbound.allowZeroHop=true fastRecieve=true"
func (f *I2PConfig) DoZero() string {
	r := ""
	if f.InAllowZeroHop == "true" {
		r += " inbound.allowZeroHop=" + f.InAllowZeroHop + " "
	}
	if f.OutAllowZeroHop == "true" {
		r += " outbound.allowZeroHop= " + f.OutAllowZeroHop + " "
	}
	if f.TransportOptions.FastReceive == "true" {
		r += " " + f.TransportOptions.FastReceive + " "
	}
	log.WithField("zeroHopSettings", r).Debug("Zero hop settings applied")
	return r
}

// Print returns the full config as a string
func (f *I2PConfig) Print() []string {
	lsk, lspk, lspsk := f.Leasesetsettings()
	return []string{
		// f.targetForPort443(),
		"inbound.length=" + f.InLength,
		"outbound.length=" + f.OutLength,
		"inbound.lengthVariance=" + f.InVariance,
		"outbound.lengthVariance=" + f.OutVariance,
		"inbound.backupQuantity=" + f.InBackupQuantity,
		"outbound.backupQuantity=" + f.OutBackupQuantity,
		"inbound.quantity=" + f.InQuantity,
		"outbound.quantity=" + f.OutQuantity,
		f.DoZero(),
		//"i2cp.fastRecieve=" + f.FastRecieve,
		"i2cp.gzip=" + f.TransportOptions.UseCompression,
		f.Reduce(),
		f.Close(),
		f.Reliability(),
		f.EncryptLease(),
		lsk, lspk, lspsk,
		f.Accesslisttype(),
		f.Accesslist(),
		f.LeaseSetEncryptionType(),
	}
}

// Accesslisttype returns the access list type
func (f *I2PConfig) Accesslisttype() string {
	if f.AccessListType == "whitelist" {
		log.Debug("Access list type set to whitelist")
		return "i2cp.enableAccessList=true"
	} else if f.AccessListType == "blacklist" {
		log.Debug("Access list type set to blacklist")
		return "i2cp.enableBlackList=true"
	} else if f.AccessListType == "none" {
		log.Debug("Access list type set to none")
		return ""
	}
	log.Debug("Access list type not set")
	return ""
}

// Accesslist returns the access list in the form of "i2cp.accessList=list"
func (f *I2PConfig) Accesslist() string {
	if f.AccessListType != "" && len(f.AccessList) > 0 {
		r := ""
		for _, s := range f.AccessList {
			r += s + ","
		}
		log.WithField("accessList", r).Debug("Access list generated")
		return "i2cp.accessList=" + strings.TrimSuffix(r, ",")
	}
	log.Debug("Access list not set")
	return ""
}

// LeaseSetEncryptionType returns the lease set encryption type in the form of "i2cp.leaseSetEncType=type"
func (f *I2PConfig) LeaseSetEncryptionType() string {
	if f.LeaseSetEncryption == "" {
		log.Debug("Using default lease set encryption type: 4,0")
		return "i2cp.leaseSetEncType=4,0"
	}
	for _, s := range strings.Split(f.LeaseSetEncryption, ",") {
		if _, err := strconv.Atoi(s); err != nil {
			log.WithField("invalidType", s).Panic("Invalid encrypted leaseSet type")
			// panic("Invalid encrypted leaseSet type: " + s)
		}
	}
	log.WithField("leaseSetEncType", f.LeaseSetEncryption).Debug("Lease set encryption type set")
	return "i2cp.leaseSetEncType=" + f.LeaseSetEncryption
}

// NewConfig returns a new config with default values or updates them with functional arguments
func NewConfig(opts ...func(*I2PConfig) error) (*I2PConfig, error) {
	config := I2PConfig{
		SamHost:                   "127.0.0.1",
		SamPort:                   "7656",
		SamMin:                    "3.0",
		SamMax:                    "3.3",
		TunName:                   "",
		InLength:                  "3",
		OutLength:                 "3",
		InQuantity:                "2",
		OutQuantity:               "2",
		InVariance:                "1",
		OutVariance:               "1",
		InBackupQuantity:          "3",
		OutBackupQuantity:         "3",
		InAllowZeroHop:            "false",
		OutAllowZeroHop:           "false",
		EncryptLeaseSet:           "false",
		LeaseSetKey:               "",
		LeaseSetPrivateKey:        "",
		LeaseSetPrivateSigningKey: "",
		ReduceIdle:                "false",
		ReduceIdleTime:            "15",
		ReduceIdleQuantity:        "1",
		CloseIdle:                 "false",
		LeaseSetEncryption:        DEFAULT_LEASESET_TYPE,
		SessionOptions: SessionOptions{
			Style:         "STREAM",
			SignatureType: "EdDSA_SHA512_Ed25519",
			FromPort:      "",
			ToPort:        "",
			Protocol:      "",
			UDPPort:       0,
		},
		TransportOptions: TransportOptions{
			UseCompression: "true",
			FastReceive:    "false",
			Reliability:    "none",
			IdleTimeout:    5 * time.Minute,
		},
	}
	for _, o := range opts {
		if err := o(&config); err != nil {
			return nil, err
		}
	}
	return &config, nil
}
