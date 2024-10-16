package encrypted_rwc

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"slices"

	"golang.org/x/crypto/chacha20poly1305"
)

const MAX_SEGMENT_SIZE = 1 << 16 // 64 KiB

type EncryptedRWC struct {
	inner io.ReadWriteCloser
	key   []byte

	receiveBuffer             []byte
	receiveNextSequenceNumber uint64
	sendNextSequenceNumber    uint64
}

func NewEncryptedRWC(rwc io.ReadWriteCloser, key []byte) (*EncryptedRWC, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("expected key size '%d' but got '%d'", chacha20poly1305.KeySize, len(key))
	}

	return &EncryptedRWC{
		inner: rwc,
		key:   key,
	}, nil
}

func (rwc *EncryptedRWC) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	// Try to read buffered plaintext data
	n := copy(p, rwc.receiveBuffer)
	if n > 0 {
		rwc.receiveBuffer = rwc.receiveBuffer[n:]
		return n, nil
	}

	// Read and decrypt from the underlying io.ReadWriteCloser
	headerBytes := make([]byte, 2+chacha20poly1305.NonceSizeX+8)
	_, err := io.ReadFull(rwc.inner, headerBytes)
	if err != nil {
		return 0, fmt.Errorf("failed to read header: %w", err)
	}

	segmentLen := uint64(binary.LittleEndian.Uint16(headerBytes[:2])) + 1
	segmentNonceBytes := headerBytes[2 : 2+chacha20poly1305.NonceSizeX]
	segmentSequenceNumber := binary.LittleEndian.Uint64(headerBytes[2+chacha20poly1305.NonceSizeX:])
	if segmentSequenceNumber != rwc.receiveNextSequenceNumber {
		return 0, fmt.Errorf("expected sequence number '%d' but got '%d'", rwc.receiveNextSequenceNumber, segmentSequenceNumber)
	}
	rwc.receiveNextSequenceNumber = rwc.receiveNextSequenceNumber + 1

	segmentEncrypted := make([]byte, segmentLen+chacha20poly1305.Overhead)
	_, err = io.ReadFull(rwc.inner, segmentEncrypted)
	if err != nil {
		return 0, fmt.Errorf("failed to read encrypted payload: %w", err)
	}

	aead, err := chacha20poly1305.NewX(rwc.key)
	if err != nil {
		return 0, fmt.Errorf("failed to create AEAD: %w", err)
	}

	rwc.receiveBuffer, err = aead.Open(nil, segmentNonceBytes, segmentEncrypted, headerBytes)
	if err != nil {
		return 0, fmt.Errorf("failed to decrypt payload: %w", err)
	}

	// Read buffered plaintext data
	n = copy(p, rwc.receiveBuffer)
	rwc.receiveBuffer = rwc.receiveBuffer[n:]
	return n, nil
}

func (rwc *EncryptedRWC) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	aead, err := chacha20poly1305.NewX(rwc.key)
	if err != nil {
		return 0, fmt.Errorf("failed to create AEAD: %w", err)
	}

	segments := slices.Chunk(p, MAX_SEGMENT_SIZE)
	for segment := range segments {
		nonce := make([]byte, chacha20poly1305.NonceSizeX)
		_, err = rand.Read(nonce)
		if err != nil {
			return 0, fmt.Errorf("failed to generate nonce: %w", err)
		}

		payloadBuffer := bytes.Buffer{}
		payloadBuffer.Write(binary.LittleEndian.AppendUint16(nil, uint16(len(segment)-1)))
		payloadBuffer.Write(nonce)
		payloadBuffer.Write(binary.LittleEndian.AppendUint64(nil, rwc.sendNextSequenceNumber))
		rwc.sendNextSequenceNumber++

		segmentEncrypted := aead.Seal(nil, nonce, segment, payloadBuffer.Bytes())
		payloadBuffer.Write(segmentEncrypted)

		_, err = rwc.inner.Write(payloadBuffer.Bytes())
		if err != nil {
			return 0, fmt.Errorf("failed to write encrypted payload: %w", err)
		}
	}

	return len(p), nil
}

func (rwc *EncryptedRWC) Close() error {
	return rwc.inner.Close()
}
