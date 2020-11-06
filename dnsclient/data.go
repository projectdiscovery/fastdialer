package dnsclient

import (
	"bytes"
	"encoding/gob"
)

type DNSData struct {
	IP4s   []string
	IP6s   []string
	CNAMEs []string
}

func (r *DNSData) Marshal() ([]byte, error) {
	var b bytes.Buffer
	enc := gob.NewEncoder(&b)
	err := enc.Encode(r)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func (r *DNSData) Unmarshal(b []byte) error {
	dec := gob.NewDecoder(bytes.NewBuffer(b))
	err := dec.Decode(&r)
	if err != nil {
		return err
	}
	return nil
}
