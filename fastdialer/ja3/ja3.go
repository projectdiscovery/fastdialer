package ja3

import (
	"crypto/sha256"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/projectdiscovery/utils/errkit"
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
	extMap["51"] = &utls.KeyShareExtension{KeyShares: keyShares(supportedCurves)}

	extensions, err := parseExtensions(ja3tokens[2], extMap)
	if err != nil {
		return nil, err
	}

	spec := &utls.ClientHelloSpec{
		CipherSuites:       cipherSuites,
		CompressionMethods: []byte{0},
		Extensions:         extensions,
		GetSessionID:       sha256.Sum256,
	}

	// The JA3 version field is the ClientHello legacy_version, which TLS 1.3
	// clients also send as TLS 1.2 (RFC 8446, section 4.1.2), so it doesn't
	// show whether the client supports TLS 1.3. When supported_versions (43)
	// is present, leave the versions zero and let utls derive them from it.
	hasSupportedVersions := slices.ContainsFunc(extensions, func(e utls.TLSExtension) bool {
		_, ok := e.(*utls.SupportedVersionsExtension)
		return ok
	})
	if !hasSupportedVersions {
		spec.TLSVersMin = vid
		spec.TLSVersMax = vid
	}

	return spec, nil
}

// keyShares returns key shares for the first curve that utls can generate a
// key for, leaving their data to be filled by [utls.UConn.ApplyPreset]. It
// returns no key shares if none of the curves qualify.
//
// utls doesn't start a TLS 1.3 handshake without a classic ECDHE key share, so
// X25519MLKEM768 comes with an X25519 share, as in Chrome, and is skipped when
// X25519 isn't among the curves.
func keyShares(curves []utls.CurveID) []utls.KeyShare {
	for _, c := range curves {
		switch c {
		case utls.X25519MLKEM768:
			if slices.Contains(curves, utls.X25519) {
				return []utls.KeyShare{{Group: c}, {Group: utls.X25519}}
			}
		case utls.X25519, utls.CurveP256, utls.CurveP384, utls.CurveP521:
			return []utls.KeyShare{{Group: c}}
		}
	}

	return []utls.KeyShare{}
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
		return nil, errkit.New("no cipher suites provided")
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

func parseExtensions(extensionToken string, extMap map[string]utls.TLSExtension) ([]utls.TLSExtension, error) {
	var extensions []utls.TLSExtension
	extensionToken = cleanup(extensionToken)
	if extensionToken == "" {
		return nil, errkit.New("no extensions provided")
	}
	exts := strings.Split(extensionToken, "-")
	for _, ext := range exts {
		te, ok := extMap[ext]
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
