package tls

import (
	tls "crypto/tls"
	"crypto/x509"
	"encoding/pem"

	"github.com/rs/zerolog"
)

var (
	log zerolog.Logger
)

// MakeTLS generates a tls.Config
func MakeTLS(clientCert, key []byte) (*tls.Config, error) {
	if clientCert == nil && key == nil {
		return new(tls.Config), nil
	}

	var err error

	cert, err := tls.X509KeyPair(clientCert, key)

	if err != nil {
		return nil, err
	}

	log.Debug().Str("key", string(key))
	log.Debug().Str("client.certificate", string(clientCert))
	log.Debug().Interface("certificate", cert)

	if err != nil {
		return nil, err
	}

	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, err := x509.SystemCertPool()

	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
		log.Warn().Err(err).Msg("Using empty cert-pool")
	} else {
		log.Info().Msg("Using system cert-pool")
	}

	for _, cert := range DecodePEM(clientCert).Certificate {
		x509Cert, err := x509.ParseCertificate(cert)
		if err != nil {
			log.Error().Err(err).Msg("issue parsing cert PEM")
		}
		rootCAs.AddCert(x509Cert)
	}

	log.Debug().Interface("root.ca", rootCAs)
	log.Debug().Interface("certificates", []tls.Certificate{cert})

	return &tls.Config{
		RootCAs:      rootCAs,
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}, nil
}

// DecodePEM builds a PEM certificate object
func DecodePEM(certPEM []byte) tls.Certificate {
	var cert tls.Certificate
	var certDER *pem.Block
	for {
		certDER, certPEM = pem.Decode(certPEM)
		if certDER == nil {
			break
		}
		if certDER.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDER.Bytes)
		}
	}

	return cert
}
