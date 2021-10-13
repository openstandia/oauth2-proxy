package sessions

import (
	"fmt"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/encryption"
	"github.com/vmihailenco/msgpack/v4"
)

// SignedOutState is used to store information about the signed out user session
type SignedOutState struct {
	IssuedAt *time.Time `msgpack:"ia,omitempty"`

	Sub string `msgpack:"s,omitempty"`
}

// EncodeSignedOutState returns an encrypted, lz4 compressed, MessagePack encoded Signed Out State
func (s *SignedOutState) EncodeSignedOutState(c encryption.Cipher, compress bool) ([]byte, error) {
	packed, err := msgpack.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("error marshalling signed out state to msgpack: %w", err)
	}

	if !compress {
		return c.Encrypt(packed)
	}

	compressed, err := lz4Compress(packed)
	if err != nil {
		return nil, err
	}
	return c.Encrypt(compressed)
}

// DecodeSignedOutState decodes a LZ4 compressed MessagePack into a Signed Out State
func DecodeSignedOutState(data []byte, c encryption.Cipher, compressed bool) (*SignedOutState, error) {
	decrypted, err := c.Decrypt(data)
	if err != nil {
		return nil, fmt.Errorf("error decrypting the signed out state: %w", err)
	}

	packed := decrypted
	if compressed {
		packed, err = lz4Decompress(decrypted)
		if err != nil {
			return nil, err
		}
	}

	var ss SignedOutState
	err = msgpack.Unmarshal(packed, &ss)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling data to session state: %w", err)
	}

	return &ss, nil
}
