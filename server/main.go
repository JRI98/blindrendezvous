package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
)

const X25519_PUBLIC_KEY_SIZE = 32

type PendingConnectionsStore struct {
	mu sync.Mutex

	pendingConnections map[string]net.Conn
}

func getMatchingConnectionOrStore(pendingConnectionsStore *PendingConnectionsStore, connection net.Conn, ownPublicKey string, targetPublicKey string) net.Conn {
	pendingConnectionsStore.mu.Lock()
	defer pendingConnectionsStore.mu.Unlock()

	if connection, exists := pendingConnectionsStore.pendingConnections[targetPublicKey]; exists {
		delete(pendingConnectionsStore.pendingConnections, targetPublicKey)
		return connection
	}

	pendingConnectionsStore.pendingConnections[ownPublicKey] = connection
	return nil
}

func handleConnection(connection net.Conn, pendingConnectionsStore *PendingConnectionsStore) {
	slog.Info("Accepted connection", slog.String("remote_address", connection.RemoteAddr().String()))

	connectionInfoBytes := make([]byte, 2*X25519_PUBLIC_KEY_SIZE)
	_, err := io.ReadFull(connection, connectionInfoBytes)
	if err != nil {
		slog.Error("Error in ReadFull", slog.Any("error", err))
		connection.Close()
		return
	}

	ownPublicKey := hex.EncodeToString(connectionInfoBytes[:X25519_PUBLIC_KEY_SIZE])
	targetPublicKey := hex.EncodeToString(connectionInfoBytes[X25519_PUBLIC_KEY_SIZE:])

	slog.Info("Received authentication info", slog.String("remote_address", connection.RemoteAddr().String()), slog.String("own_public_key", ownPublicKey), slog.String("target_public_key", targetPublicKey))

	matchingConnection := getMatchingConnectionOrStore(pendingConnectionsStore, connection, ownPublicKey, targetPublicKey)
	if matchingConnection == nil {
		return
	}

	defer func() {
		connection.Close()
		slog.Info("Closed connection", slog.String("remote_address", connection.RemoteAddr().String()))

		matchingConnection.Close()
		slog.Info("Closed connection", slog.String("remote_address", matchingConnection.RemoteAddr().String()))
	}()

	go func() {
		_, err := io.Copy(matchingConnection, connection)
		if err != nil {
			slog.Error("Error in Copy from matching connection to connection", slog.Any("error", err))
		}
	}()

	_, err = io.Copy(connection, matchingConnection)
	if err != nil {
		slog.Error("Error in Copy from connection to matching connection", slog.Any("error", err))
	}
}

func run(ctx context.Context, shutdownWaitGroup *sync.WaitGroup, cancelCtx context.CancelFunc, pendingConnectionsStore *PendingConnectionsStore, port uint64) {
	defer shutdownWaitGroup.Done()
	defer cancelCtx()
	defer slog.Warn("Shutting down")

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		slog.Error("Error in Listen", slog.Any("error", err))
		return
	}
	defer listener.Close()

	// Close the listener when the context is done to unblock Accept
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	slog.Info("Listening for TCP connections", slog.Uint64("port", port))

	for {
		connection, err := listener.Accept()
		if err != nil {
			slog.Error("Error in Accept", slog.Any("error", err))
			return
		}

		go handleConnection(connection, pendingConnectionsStore)
	}
}

func main() {
	var PORT uint64

	flag.Uint64Var(&PORT, "port", 0, "port")
	flag.Parse()

	if PORT == 0 {
		flag.Usage()
		return
	}

	ctx, cancelCtx := context.WithCancel(context.Background())
	shutdownWaitGroup := &sync.WaitGroup{}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))

	pendingConnectionStore := &PendingConnectionsStore{
		pendingConnections: make(map[string]net.Conn),
	}

	shutdownWaitGroup.Add(1)
	go run(ctx, shutdownWaitGroup, cancelCtx, pendingConnectionStore, PORT)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	select {
	case <-ctx.Done():
	case <-quit:
		cancelCtx()
	}

	shutdownWaitGroup.Wait()
}
