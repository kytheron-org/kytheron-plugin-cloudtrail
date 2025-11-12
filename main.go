package main

import (
	"encoding/json"
	"fmt"
	pb "github.com/kytheron-org/kytheron-plugin-go/plugin"
	"google.golang.org/grpc"
	"log"
	"math"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// Start our GRPC server. This receives a RawLog, and
	// responds with 1-N parsed logs
	plugin := &cloudtrail{}
	socket, err := os.CreateTemp(os.Getenv("PLUGIN_UNIX_SOCKET_DIR"), "cloudtrail")
	if err != nil {
		log.Fatal(err)
	}
	path := socket.Name()
	if err := socket.Close(); err != nil {
		log.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		log.Fatal(err)
	}

	l, err := net.Listen("unix", path)
	if err != nil {
		log.Fatal(err)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan bool, 1)

	grpcServer := grpc.NewServer(
		grpc.MaxSendMsgSize(math.MaxInt64), // 50MB example
		grpc.MaxRecvMsgSize(math.MaxInt64),
	)
	pb.RegisterParserPluginServer(grpcServer, plugin)

	go func() {
		log.Printf("gRPC server listening on %v", l.Addr())
		if err := grpcServer.Serve(l); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	go func() {
		select {
		case sig := <-sigs:
			println("Received signal:", sig)
			done <- true // Signal main goroutine to exit
		}
	}()

	handshake := map[string]interface{}{
		"type": "handshake",
		"addr": l.Addr().String(),
	}
	contents, err := json.Marshal(handshake)
	fmt.Println(string(contents))
	<-done
}
