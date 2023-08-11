// ja3 is a package for creating JA3 fingerprints from TLS clients.
// The original extension map and numeric id=>tls extension mapping is from https://github.com/CUCyber
package ja3

import (
	utls "github.com/refraction-networking/utls"
	"golang.org/x/exp/maps"
)

// extMap maps extension values to the TLSExtension object associated with the
// number. Some values are not put in here because they must be applied in a
// special way. For example, "10" is the SupportedCurves extension which is also
// used to calculate the JA3 signature. These JA3-dependent values are applied
// after the instantiation of the map.
var defaultExtensionMap = map[string]utls.TLSExtension{
	"0": &utls.SNIExtension{},
	"5": &utls.StatusRequestExtension{},
	// These are applied later
	// "10": &tls.SupportedCurvesExtension{...}
	// "11": &tls.SupportedPointsExtension{...}
	"13": &utls.SignatureAlgorithmsExtension{
		SupportedSignatureAlgorithms: []utls.SignatureScheme{
			utls.ECDSAWithP256AndSHA256,
			utls.PSSWithSHA256,
			utls.PKCS1WithSHA256,
			utls.ECDSAWithP384AndSHA384,
			utls.PSSWithSHA384,
			utls.PKCS1WithSHA384,
			utls.PSSWithSHA512,
			utls.PKCS1WithSHA512,
			utls.PKCS1WithSHA1,
		},
	},
	"16": &utls.ALPNExtension{
		AlpnProtocols: []string{"h2", "http/1.1"},
	},
	"18": &utls.SCTExtension{},
	"21": &utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
	"23": &utls.ExtendedMasterSecretExtension{},
	"28": &utls.FakeRecordSizeLimitExtension{},
	"35": &utls.SessionTicketExtension{},
	"43": &utls.SupportedVersionsExtension{Versions: []uint16{
		utls.GREASE_PLACEHOLDER,
		utls.VersionTLS13,
		utls.VersionTLS12,
		utls.VersionTLS11,
		utls.VersionTLS10}},
	"44": &utls.CookieExtension{},
	"45": &utls.PSKKeyExchangeModesExtension{
		Modes: []uint8{
			utls.PskModeDHE,
		}},
	"51":    &utls.KeyShareExtension{KeyShares: []utls.KeyShare{}},
	"13172": &utls.NPNExtension{},
	"65281": &utls.RenegotiationInfoExtension{
		Renegotiation: utls.RenegotiateOnceAsClient,
	},
}

func getExtensionMap() map[string]utls.TLSExtension {
	return maps.Clone(defaultExtensionMap)
}
