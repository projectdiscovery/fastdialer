package fastdialer

type NoAddressFoundError struct{}

func (m *NoAddressFoundError) Error() string {
	return "no address found for host"
}
