package main

import (
	"encoding/json"
	"fmt"
	"github.com/kytheron-org/kytheron-plugin-framework/listener"
	pb "github.com/kytheron-org/kytheron-plugin-go/plugin"
	"google.golang.org/grpc"
	"log"
	"math"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// Start our GRPC server. This receives a RawLog, and
	// responds with 1-N parsed logs
	plugin := &cloudtrail{}
	l, err := listener.NewSocket(os.Getenv("PLUGIN_UNIX_SOCKET_DIR"), "cloudtrail")
	if err != nil {
		log.Fatal(err)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan bool, 1)

	var maxMessageSize int = math.MaxInt
	grpcServer := grpc.NewServer(
		grpc.MaxSendMsgSize(maxMessageSize), // 50MB example
		grpc.MaxRecvMsgSize(maxMessageSize),
	)
	pb.RegisterPluginServer(grpcServer, plugin)
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
