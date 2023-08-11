package ja3

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// ParseWithJa3Hash a JA3 string and returns a ClientHelloSpec
// ja3 string format: SSLVersion,CipherSuites,Extensions,SupportedCurves,SupportedPoints
func ParseWithJa3(ja3 string) (*utls.ClientHelloSpec, error) {
	ja3tokens := strings.Split(ja3, ",")
	if len(ja3tokens) != 5 {
		return nil, fmt.Errorf("invalid ja3 string: %s", ja3)
	}

	vid, err := parseVersion(ja3tokens[0])
	if err != nil {
		return nil, err
	}

	cipherSuites, err := parseCipherSuites(ja3tokens[1])
	if err != nil {
		return nil, err
	}

	extensions, err := parseExtensions(ja3tokens[2])
	if err != nil {
		return nil, err
	}

	supportedCurves, err := parseSupportedCurves(ja3tokens[3])
	if err != nil {
		return nil, err
	}

	supportedPoints, err := parseSupportedPoints(ja3tokens[4])
	if err != nil {
		return nil, err
	}

	extMap := getExtensionMap()
	extMap["10"] = &utls.SupportedCurvesExtension{Curves: supportedCurves}
	extMap["11"] = &utls.SupportedPointsExtension{SupportedPoints: supportedPoints}

	return &utls.ClientHelloSpec{
		TLSVersMin:         vid,
		TLSVersMax:         vid,
		CipherSuites:       cipherSuites,
		CompressionMethods: []byte{0},
		Extensions:         extensions,
		GetSessionID:       sha256.Sum256,
	}, nil
}

func cleanup(s string) string {
	return strings.TrimSpace(s)
}

func parseVersion(version string) (uint16, error) {
	vid64, err := strconv.ParseUint(version, 10, 16)
	if err != nil {
		return 0, err
	}
	return uint16(vid64), nil
}

func parseCipherSuites(cipherToken string) ([]uint16, error) {
	cipherToken = cleanup(cipherToken)
	if cipherToken == "" {
		return nil, errors.New("no cipher suites provided")
	}
	ciphers := strings.Split(cipherToken, "-")
	var cipherSuites []uint16
	for _, cipher := range ciphers {
		cid, err := strconv.ParseUint(cipher, 10, 16)
		if err != nil {
			return nil, err
		}
		cipherSuites = append(cipherSuites, uint16(cid))
	}
	return cipherSuites, nil
}

func parseExtensions(extensionToken string) ([]utls.TLSExtension, error) {
	var extensions []utls.TLSExtension
	extensionToken = cleanup(extensionToken)
	if extensionToken == "" {
		return nil, errors.New("no extensions provided")
	}
	exts := strings.Split(extensionToken, "-")
	for _, ext := range exts {
		te, ok := defaultExtensionMap[ext]
		if !ok {
			return nil, ErrExtensionNotExist(ext)
		}
		extensions = append(extensions, te)
	}
	return extensions, nil
}

func parseSupportedCurves(supportedCurvesToken string) ([]utls.CurveID, error) {
	var supportedCurves []utls.CurveID
	supportedCurvesToken = cleanup(supportedCurvesToken)
	if supportedCurvesToken == "" {
		return supportedCurves, nil
	}
	curves := strings.Split(supportedCurvesToken, "-")
	for _, c := range curves {
		cid, err := strconv.ParseUint(c, 10, 16)
		if err != nil {
			return nil, err
		}
		supportedCurves = append(supportedCurves, utls.CurveID(cid))
	}
	return supportedCurves, nil
}

func parseSupportedPoints(supportedPointsToken string) ([]byte, error) {
	var supportedPoints []byte
	supportedPointsToken = cleanup(supportedPointsToken)
	if supportedPointsToken == "" {
		return supportedPoints, nil
	}
	points := strings.Split(supportedPointsToken, "-")
	for _, p := range points {
		pid, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return nil, err
		}
		supportedPoints = append(supportedPoints, byte(pid))
	}
	return supportedPoints, nil
}

func ParseWithRaw(rawClientHello []byte) (*utls.ClientHelloSpec, error) {
	fingerprinter := &utls.Fingerprinter{}
	return fingerprinter.FingerprintClientHello(rawClientHello)
}
