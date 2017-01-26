package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func init() {
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, `
Usage: slack-dash [Slack API Token] [MAC Address] [Interface] [Channel]
                  [Message]

`)
		flag.PrintDefaults()
	}
}

func main() {
	flag.Parse()

	if flag.NArg() < 5 {
		flag.Usage()
		os.Exit(1)
	}

	token := flag.Arg(0)

	addr, err := net.ParseMAC(flag.Arg(1))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ifname := flag.Arg(2)
	ch := flag.Arg(3)
	msg := flag.Arg(4)

	dash := NewSlackDash(token, ifname, addr, ch, msg)

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	go func() {
		<-sig
		fmt.Fprint(os.Stderr, "Stopping...")
		dash.Stop()
	}()

	err = dash.Start()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "done.")
}
