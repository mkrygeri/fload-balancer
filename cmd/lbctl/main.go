package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	pb "fload-balancer/api/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	addr := flag.String("addr", "localhost:50051", "gRPC server address")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	conn, err := grpc.NewClient(*addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	client := pb.NewLoadBalancerServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	switch args[0] {
	case "backends":
		cmdBackends(ctx, client)
	case "add-backend":
		cmdAddBackend(ctx, client, args[1:])
	case "remove-backend":
		cmdRemoveBackend(ctx, client, args[1:])
	case "sessions":
		cmdSessions(ctx, client)
	case "flush-sessions":
		cmdFlushSessions(ctx, client)
	case "stats":
		cmdBackendStats(ctx, client)
	case "flow-stats":
		cmdFlowStats(ctx, client)
	case "seq-stats":
		cmdSeqStats(ctx, client)
	case "config":
		cmdGetConfig(ctx, client)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", args[0])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `Usage: lbctl [flags] <command>

Commands:
  backends         List all backends
  add-backend      Add a backend (ip:port)
  remove-backend   Remove a backend by index
  sessions         List active sessions
  flush-sessions   Remove all sessions
  stats            Show per-backend statistics
  flow-stats       Show per-flow-type statistics
  seq-stats        Show sequence tracking statistics
  config           Show current configuration

Flags:`)
	flag.PrintDefaults()
}

func cmdBackends(ctx context.Context, c pb.LoadBalancerServiceClient) {
	resp, err := c.ListBackends(ctx, &pb.ListBackendsRequest{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "INDEX\tIP\tPORT\tACTIVE\tWEIGHT")
	for _, b := range resp.Backends {
		fmt.Fprintf(w, "%d\t%s\t%d\t%v\t%d\n", b.Index, b.Ip, b.Port, b.Active, b.Weight)
	}
	w.Flush()
}

func cmdAddBackend(ctx context.Context, c pb.LoadBalancerServiceClient, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: lbctl add-backend <ip> [port]")
		os.Exit(1)
	}
	ip := args[0]
	var port uint32
	if len(args) > 1 {
		fmt.Sscanf(args[1], "%d", &port)
	}
	resp, err := c.AddBackend(ctx, &pb.AddBackendRequest{Ip: ip, Port: port})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("added backend at index %d\n", resp.Index)
}

func cmdRemoveBackend(ctx context.Context, c pb.LoadBalancerServiceClient, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: lbctl remove-backend <index>")
		os.Exit(1)
	}
	var idx uint32
	fmt.Sscanf(args[0], "%d", &idx)
	_, err := c.RemoveBackend(ctx, &pb.RemoveBackendRequest{Index: idx})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("removed backend %d\n", idx)
}

func cmdSessions(ctx context.Context, c pb.LoadBalancerServiceClient) {
	resp, err := c.GetSessions(ctx, &pb.GetSessionsRequest{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "SRC\tDST\tBACKEND\tFLOW_TYPE\tPACKETS\tBYTES")
	for _, s := range resp.Sessions {
		src := fmt.Sprintf("%s:%d", s.SrcIp, s.SrcPort)
		dst := fmt.Sprintf("%s:%d", s.DstIp, s.DstPort)
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%d\t%d\n",
			src, dst, s.BackendIdx, s.FlowType, s.Packets, s.Bytes)
	}
	w.Flush()
}

func cmdFlushSessions(ctx context.Context, c pb.LoadBalancerServiceClient) {
	resp, err := c.FlushSessions(ctx, &pb.FlushSessionsRequest{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("flushed %d sessions\n", resp.Flushed)
}

func cmdBackendStats(ctx context.Context, c pb.LoadBalancerServiceClient) {
	resp, err := c.GetBackendStats(ctx, &pb.GetBackendStatsRequest{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "INDEX\tIP\tPACKETS\tBYTES")
	for _, s := range resp.Stats {
		fmt.Fprintf(w, "%d\t%s\t%d\t%d\n", s.Index, s.Ip, s.RxPackets, s.RxBytes)
	}
	w.Flush()
}

func cmdFlowStats(ctx context.Context, c pb.LoadBalancerServiceClient) {
	resp, err := c.GetFlowTypeStats(ctx, &pb.GetFlowTypeStatsRequest{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "FLOW_TYPE\tPACKETS\tBYTES")
	for _, s := range resp.Stats {
		fmt.Fprintf(w, "%s\t%d\t%d\n", s.FlowType, s.Packets, s.Bytes)
	}
	w.Flush()
}

func cmdSeqStats(ctx context.Context, c pb.LoadBalancerServiceClient) {
	resp, err := c.GetSequenceStats(ctx, &pb.GetSequenceStatsRequest{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "SOURCE\tFLOW_TYPE\tRECEIVED\tGAPS\tDUPLICATES\tOOO\tLAST_SEQ\tEXPECTED")
	for _, s := range resp.Stats {
		src := fmt.Sprintf("%s:%d", s.SrcIp, s.SrcPort)
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\n",
			src, s.FlowType, s.TotalReceived, s.Gaps, s.Duplicates,
			s.OutOfOrder, s.LastSeq, s.ExpectedNext)
	}
	w.Flush()
}

func cmdGetConfig(ctx context.Context, c pb.LoadBalancerServiceClient) {
	resp, err := c.GetConfig(ctx, &pb.GetConfigRequest{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	cfg := resp.Config
	fmt.Printf("VIP IP:           %s\n", cfg.VipIp)
	fmt.Printf("VIP Ports:        %v\n", cfg.VipPorts)
	fmt.Printf("Seq Tracking:     %v\n", cfg.SeqTracking)
	fmt.Printf("Seq Window Size:  %d\n", cfg.SeqWindowSize)
	fmt.Printf("Session Timeout:  %ds\n", cfg.SessionTimeoutS)
	fmt.Printf("Health Interval:  %ds\n", cfg.HealthIntervalS)
	fmt.Printf("Health Timeout:   %ds\n", cfg.HealthTimeoutS)
}
