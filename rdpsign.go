package rdpsign

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

var secureSettings = [][2]string{
	{"full address:s:", "Full Address"},
	{"alternate full address:s:", "Alternate Full Address"},
	{"pcb:s:", "PCB"},
	{"use redirection server name:i:", "Use Redirection Server Name"},
	{"server port:i:", "Server Port"},
	{"negotiate security layer:i:", "Negotiate Security Layer"},
	{"enablecredsspsupport:i:", "EnableCredSspSupport"},
	{"disableconnectionsharing:i:", "DisableConnectionSharing"},
	{"autoreconnection enabled:i:", "AutoReconnection Enabled"},
	{"gatewayhostname:s:", "GatewayHostname"},
	{"gatewayusagemethod:i:", "GatewayUsageMethod"},
	{"gatewayprofileusagemethod:i:", "GatewayProfileUsageMethod"},
	{"gatewaycredentialssource:i:", "GatewayCredentialsSource"},
	{"support url:s:", "Support URL"},
	{"promptcredentialonce:i:", "PromptCredentialOnce"},
	{"require pre-authentication:i:", "Require pre-authentication"},
	{"pre-authentication server address:s:", "Pre-authentication server address"},
	{"alternate shell:s:", "Alternate Shell"},
	{"shell working directory:s:", "Shell Working Directory"},
	{"remoteapplicationprogram:s:", "RemoteApplicationProgram"},
	{"remoteapplicationexpandworkingdir:s:", "RemoteApplicationExpandWorkingdir"},
	{"remoteapplicationmode:i:", "RemoteApplicationMode"},
	{"remoteapplicationguid:s:", "RemoteApplicationGuid"},
	{"remoteapplicationname:s:", "RemoteApplicationName"},
	{"remoteapplicationicon:s:", "RemoteApplicationIcon"},
	{"remoteapplicationfile:s:", "RemoteApplicationFile"},
	{"remoteapplicationfileextensions:s:", "RemoteApplicationFileExtensions"},
	{"remoteapplicationcmdline:s:", "RemoteApplicationCmdLine"},
	{"remoteapplicationexpandcmdline:s:", "RemoteApplicationExpandCmdLine"},
	{"prompt for credentials:i:", "Prompt For Credentials"},
	{"authentication level:i:", "Authentication Level"},
	{"audiomode:i:", "AudioMode"},
	{"redirectdrives:i:", "RedirectDrives"},
	{"redirectprinters:i:", "RedirectPrinters"},
	{"redirectcomports:i:", "RedirectCOMPorts"},
	{"redirectsmartcards:i:", "RedirectSmartCards"},
	{"redirectposdevices:i:", "RedirectPOSDevices"},
	{"redirectclipboard:i:", "RedirectClipboard"},
	{"devicestoredirect:s:", "DevicesToRedirect"},
	{"drivestoredirect:s:", "DrivesToRedirect"},
	{"loadbalanceinfo:s:", "LoadBalanceInfo"},
	{"redirectdirectx:i:", "RedirectDirectX"},
	{"rdgiskdcproxy:i:", "RDGIsKDCProxy"},
	{"kdcproxyname:s:", "KDCProxyName"},
	{"eventloguploadaddress:s:", "EventLogUploadAddress"},
}

type Signer struct {
	rsaPub  *x509.Certificate
	rsaPriv *rsa.PrivateKey
	cert    []byte
}

func NewSigner(cert, key string) (*Signer, error) {
	// parse cert
	b, err := os.ReadFile(cert)
	if err != nil {
		return nil, err
	}
	cblock, _ := pem.Decode(b)
	if cblock == nil {
		return nil, fmt.Errorf("could not decode PEM certificate")
	}

	rsaPub, err := x509.ParseCertificate(cblock.Bytes)
	if err != nil {
		return nil, err
	}

	// parse key
	rsaPriv, err := parseKey(key)
	if err != nil {
		return nil, err
	}

	return &Signer{
		rsaPub:  rsaPub,
		rsaPriv: rsaPriv,
		cert:    cblock.Bytes,
	}, nil
}

func (s *Signer) SignRdp(content string) ([]byte, error) {
	var settings, signnames, signlines, optionlines []string
	fulladdress := ""
	alternatefulladdress := ""

	lines := strings.Split(content, "\r\n")
	for _, v := range lines {
		if strings.HasPrefix(v, "full address:s:") {
			fulladdress = v[15:]
		} else if strings.HasPrefix(v, "alternate full address:s:") {
			alternatefulladdress = v[25:]
		} else if strings.HasPrefix(v, "signature:s:") {
			continue
		} else if strings.HasPrefix(v, "signscope:s:") {
			continue
		} else if strings.Trim(v, " ") == "" {
			continue
		}
		settings = append(settings, v)
	}

	// prevent hacks via alternate full address
	if fulladdress != "" && alternatefulladdress == "" {
		settings = append(settings, "alternate full address:s:"+fulladdress)
	}

	hits := make([]bool, len(secureSettings))
	for _, v := range settings {
		matched := false
		for index, s := range secureSettings {
			if strings.HasPrefix(v, s[0]) {
				if !hits[index] {
					signnames = append(signnames, s[1])
					signlines = append(signlines, v)
					hits[index] = true
				} else {
					return nil, errors.New("duplicate settings: " + v)
				}
				matched = true
			}
		}
		if !matched {
			optionlines = append(optionlines, v)
		}
	}

	msgText := strings.Join(signlines, "\r\n") + "\r\n" +
		"signscope:s:" + strings.Join(signnames, ",") + "\r\n\x00"

	optionText := strings.Join(optionlines, "\r\n")

	msgBlob, err := convertToUTF16le(msgText)
	if err != nil {
		return nil, err
	}

	// sign the data with RSASHA256
	sd, err := s.signDataSha256(msgBlob)
	if err != nil {
		return nil, err
	}

	w := new(bytes.Buffer)
	// The Microsoft rdpsign.exe adds a 12 byte header to the signature
	// before it gets base64 encoded
	// The meaning of the first 8 bytes is still unknown
	binary.Write(w, binary.LittleEndian, uint32(0x00010001))
	binary.Write(w, binary.LittleEndian, uint32(0x00000001))
	binary.Write(w, binary.LittleEndian, uint32(len(sd)))
	binary.Write(w, binary.LittleEndian, sd)
	signature := base64.StdEncoding.EncodeToString(w.Bytes())

	signedRdpSettings := strings.Join(signlines, "\r\n") + "\r\n" +
		"signscope:s:" + strings.Join(signnames, ",") + "\r\n" +
		"signature:s:" + signature + "\r\n"

	if len(optionText) > 2 {
		signedRdpSettings = optionText + "\r\n" + signedRdpSettings
	}

	return []byte(signedRdpSettings), nil
}

type SignedDataObject struct {
	ID         asn1.ObjectIdentifier //signedData oid: 1.2.840.113549.1.7.2
	SignedData SignedData            `asn1:"explicit,tag:0"`
}

/*
RFC 2315: 9.1 SignedData type
The signed-data content type shall have ASN.1 type SignedData:

    SignedData ::= SEQUENCE {
     version Version,
     digestAlgorithms DigestAlgorithmIdentifiers,
     contentInfo ContentInfo,
     certificates
        [0] IMPLICIT ExtendedCertificatesAndCertificates
          OPTIONAL,
     crls
       [1] IMPLICIT CertificateRevocationLists OPTIONAL,
     signerInfos SignerInfos }
*/

// why the field Certificate is not Certificates(set) ?
// process Certificate in functions
// Ignore crls(CertificateRevocationLists), hsh 2017.11.15
type SignedData struct {
	Version          version
	DigestAlgorithms digestAlgorithmIdentifiers `asn1:"set"`
	ContentInfo      contentInfo                //data oid: 1.2.840.113549.1.7.1
	Certificate      asn1.RawValue              `asn1:"optional,explicit,tag:0"`
	SignerInfos      signerInfos                `asn1:"set"`
}

type version int
type digestAlgorithmIdentifiers []pkix.AlgorithmIdentifier

type AlgorithmIdentifier struct {
	ID asn1.ObjectIdentifier
}

/*
	    ContentInfo ::= SEQUENCE {
	     contentType ContentType,
	     content
	       [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }

		ContentType ::= OBJECT IDENTIFIER
*/
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

/*
SignerInfos ::= SET OF SignerInfo

	SignerInfo ::= SEQUENCE {
	  version Version,
	  issuerAndSerialNumber IssuerAndSerialNumber,
	  digestAlgorithm DigestAlgorithmIdentifier,
	  authenticatedAttributes
	    [0] IMPLICIT Attributes OPTIONAL,
	  digestEncryptionAlgorithm
	    DigestEncryptionAlgorithmIdentifier,
	  encryptedDigest EncryptedDigest,
	  unauthenticatedAttributes
	    [1] IMPLICIT Attributes OPTIONAL }
*/
type signerInfos []signerInfo

type signerInfo struct {
	Version                   version
	IssuerAndSerialNumber     IssuerAndSerialNumber
	DigestAlgorithm           pkix.AlgorithmIdentifier
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           encryptedDigest
}

type IssuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type encryptedDigest []byte

// Sign the data with SHA256 hash algorithms as defined in FIPS 180-4.
func (s *Signer) signDataSha256(data []byte) ([]byte, error) {
	// hash data
	hashed := sha256.Sum256(data)

	// sign data
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.rsaPriv, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, err
	}

	// prepare SignedData struct
	digestAlgo := pkix.AlgorithmIdentifier{
		Algorithm:  asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, //SHA256
		Parameters: asn1.NullRawValue,
	}

	contentInfo := contentInfo{
		ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}, //data
	}

	issuerSN := IssuerAndSerialNumber{
		Issuer:       asn1.RawValue{FullBytes: s.rsaPub.RawIssuer},
		SerialNumber: s.rsaPub.SerialNumber,
	}

	signer := signerInfo{
		Version:               2,
		IssuerAndSerialNumber: issuerSN,
		DigestAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1},
			Parameters: asn1.NullRawValue},
		DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1},
			Parameters: asn1.NullRawValue},
		EncryptedDigest: signature,
	}
	//SignerInfos
	signedData := SignedData{
		Version:          1,
		DigestAlgorithms: digestAlgorithmIdentifiers{digestAlgo},
		ContentInfo:      contentInfo,
		Certificate:      asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: s.cert},
		SignerInfos:      signerInfos{signer},
	}
	sobj := SignedDataObject{
		ID:         asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2},
		SignedData: signedData,
	}

	return asn1.Marshal(sobj)
}

func parseKey(keyFile string) (*rsa.PrivateKey, error) {
	// parse key
	b, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	kblock, _ := pem.Decode(b)
	if kblock == nil {
		return nil, fmt.Errorf("could not decode PEM key")
	}

	switch kblock.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(kblock.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(kblock.Bytes)
		if err != nil {
			return nil, err
		}

		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}

		return nil, fmt.Errorf("key was not and RSA private key")
	}

	return nil, fmt.Errorf("could not parse private key")
}

func convertToUTF16le(str string) ([]byte, error) {
	if len(str) == 0 {
		return nil, errors.New("string is empty")
	}

	b := []byte(str)
	rbuf := make([]rune, len(str))
	var rlen uint32 = 0
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		//Debug(2, "%c %v\n", r, size)
		rbuf[rlen] = r
		rlen++
		b = b[size:]
	}

	ubuf := utf16.Encode(rbuf[:rlen])

	bbuf := make([]byte, 2*len(ubuf))
	n := 0
	for _, u := range ubuf {

		bbuf[n] = byte(u & 0xff)
		n++
		bbuf[n] = byte((u >> 8) & 0xff)
		n++
	}
	return bbuf, nil
}
