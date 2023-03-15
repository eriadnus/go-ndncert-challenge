package ca

import (
	enc "github.com/zjkmxy/go-ndn/pkg/encoding"
	"github.com/zjkmxy/go-ndn/pkg/ndn"
)

type RequestType int64
type _Certificate ndn.Data // Mocked out version of a certificate

const (
	Probe RequestType = iota
	New
	Revoke
	Renew
)

func OnNewRenewRevoke(i ndn.Interest, r RequestType) {
	// TODO: Verify CA Cert's Validity - NDN Security not released.

	// TODO: Get Application Parameters - No way to decode AppParams().

	// TODO: Derive shared ecdh secret - No way to decode AppParams() and non-trivial implementation.

	// TODO: Verify identity name - No Certificate, but done manually below.

	switch r {
	case New:
		break
	default:
		break
	}
}

func OnNew(ecdhKey enc.Buffer, cert enc.Buffer) {
	// TODO: Validate the certificate is still valid during this time interval
	// TODO: Validate the certificate as self-signed
	// TODO: Verify signature for interest packet
}
