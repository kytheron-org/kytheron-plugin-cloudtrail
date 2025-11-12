package main

import (
	"context"
	"encoding/json"
	pb "github.com/kytheron-org/kytheron-plugin-go/plugin"
)

type cloudtrail struct {
	pb.UnimplementedParserPluginServer
}

var _ pb.ParserPluginServer = cloudtrail{}

func (c cloudtrail) GetMetadata(ctx context.Context, empty *pb.Empty) (*pb.ParserMetadata, error) {
	return nil, nil
}

func (c cloudtrail) Configure(ctx context.Context, req *pb.ConfigureRequest) (*pb.ConfigureResponse, error) {
	return nil, nil
}

func (c cloudtrail) ParseLog(log *pb.RawLog, srv pb.ParserPlugin_ParseLogServer) error {
	var payload struct {
		Records []any
	}
	if err := json.Unmarshal(log.Data, &payload); err != nil {
		return err
	}

	for _, record := range payload.Records {
		data, err := json.Marshal(record)
		if err != nil {
			return err
		}
		if err := srv.Send(&pb.ParsedLog{
			SourceName: "TBD",
			SourceType: "cloudtrail",
			Data:       data,
		}); err != nil {
			return err
		}
	}

	return nil
}
