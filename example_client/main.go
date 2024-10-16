package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"slices"
	"sync"

	"github.com/JRI98/blindrendezvous/encrypted_rwc"
)

const X25519_PUBLIC_KEY_SIZE = 32

func run(ctx context.Context, shutdownWaitGroup *sync.WaitGroup, cancelCtx context.CancelFunc, serverAddress string, senderFilePath string, receiverFilePath string) {
	defer shutdownWaitGroup.Done()
	defer cancelCtx()
	defer slog.Warn("Shutting down")

	// Handle key generation
	ecdhPrivateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		slog.Error("Error in GenerateKey", slog.Any("error", err))
		return
	}

	ecdhPublicKey := ecdhPrivateKey.PublicKey()

	fmt.Println("My public key:", hex.EncodeToString(ecdhPublicKey.Bytes()))

	fmt.Print("Insert peer public key: ")
	peerInfoBytes := make([]byte, 2*X25519_PUBLIC_KEY_SIZE) // Multiply by 2 to account for hexadecimal encoding
	_, err = io.ReadFull(os.Stdin, peerInfoBytes)
	if err != nil {
		slog.Error("Error in ReadFull", slog.Any("error", err))
		return
	}

	peerEcdhPublicKeyBytes, err := hex.DecodeString(string(peerInfoBytes))
	if err != nil {
		slog.Error("Error in DecodeString", slog.Any("error", err))
		return
	}

	peerEcdhPublicKey, err := ecdh.X25519().NewPublicKey(peerEcdhPublicKeyBytes)
	if err != nil {
		slog.Error("Error in PublicKeyFromBytes", slog.Any("error", err))
		return
	}

	key, err := ecdhPrivateKey.ECDH(peerEcdhPublicKey)
	if err != nil {
		slog.Error("Error in ECDH", slog.Any("error", err))
		return
	}

	// Connect to server
	connection, err := net.Dial("tcp", serverAddress)
	if err != nil {
		slog.Error("Error in Dial", slog.Any("error", err))
		return
	}
	defer connection.Close()

	// Close the listener when the context is done to unblock Accept
	go func() {
		<-ctx.Done()
		connection.Close()
	}()

	slog.Info("Connected to server", slog.String("server_address", serverAddress))

	// Send handshake info to server
	_, err = connection.Write(slices.Concat(ecdhPublicKey.Bytes(), peerEcdhPublicKey.Bytes()))
	if err != nil {
		slog.Error("Error in authentication Write", slog.Any("error", err))
		return
	}

	// Create encrypted connection
	encryptedConnection, err := encrypted_rwc.NewEncryptedRWC(connection, key)
	if err != nil {
		slog.Error("Error in NewEncryptedRWC", slog.Any("error", err))
		return
	}
	defer encryptedConnection.Close()

	waitGroup := &sync.WaitGroup{}

	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()

		info, err := os.Stat(senderFilePath)
		if err != nil {
			slog.Error("Error in Stat", slog.Any("error", err))
			cancelCtx()
			return
		}

		file, err := os.Open(senderFilePath)
		if err != nil {
			slog.Error("Error in Open", slog.Any("error", err))
			cancelCtx()
			return
		}
		defer file.Close()

		_, err = encryptedConnection.Write(binary.LittleEndian.AppendUint64(nil, uint64(info.Size())))
		if err != nil {
			slog.Error("Error in Write", slog.Any("error", err))
			cancelCtx()
			return
		}

		_, err = io.Copy(encryptedConnection, file)
		if err != nil {
			slog.Error("Error in Copy", slog.Any("error", err))
			cancelCtx()
			return
		}
	}()

	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()

		file, err := os.Create(receiverFilePath)
		if err != nil {
			slog.Error("Error in Create", slog.Any("error", err))
			cancelCtx()
			return
		}
		defer file.Close()

		sizeBytes := make([]byte, 8)
		_, err = io.ReadFull(encryptedConnection, sizeBytes)
		if err != nil {
			slog.Error("Error in ReadFull", slog.Any("error", err))
			cancelCtx()
			return
		}

		size := int64(binary.LittleEndian.Uint64(sizeBytes))

		_, err = io.CopyN(file, encryptedConnection, size)
		if err != nil {
			slog.Error("Error in Copy", slog.Any("error", err))
			cancelCtx()
			return
		}
	}()

	waitGroup.Wait()
}

func main() {
	var SERVER_ADDRESS string
	var SENDER_FILE_PATH string
	var RECEIVER_FILE_PATH string

	flag.StringVar(&SERVER_ADDRESS, "server", "", "server address")
	flag.StringVar(&SENDER_FILE_PATH, "sender-file", "", "sender file path")
	flag.StringVar(&RECEIVER_FILE_PATH, "receiver-file", "", "receiver file path")
	flag.Parse()

	if SERVER_ADDRESS == "" || SENDER_FILE_PATH == "" || RECEIVER_FILE_PATH == "" {
		flag.Usage()
		return
	}

	ctx, cancelCtx := context.WithCancel(context.Background())
	shutdownWaitGroup := &sync.WaitGroup{}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))

	shutdownWaitGroup.Add(1)
	go run(ctx, shutdownWaitGroup, cancelCtx, SERVER_ADDRESS, SENDER_FILE_PATH, RECEIVER_FILE_PATH)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	select {
	case <-ctx.Done():
	case <-quit:
		cancelCtx()
	}

	shutdownWaitGroup.Wait()
}
