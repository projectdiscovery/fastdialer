package fastdialer

type NoAddressFoundError struct{}

func (m *NoAddressFoundError) Error() string {
	return "no address found for host"
}

type NoAddressAllowedError struct{}

func (m *NoAddressAllowedError) Error() string {
	return "no allowed address was found for host"
}
