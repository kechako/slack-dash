package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/nlopes/slack"
)

var (
	slackAPIToken     string
	dashButtonMACAddr string
)

type SlackDash struct {
	client *slack.Client

	ifname   string
	iface    *net.Interface
	dashAddr net.HardwareAddr

	stopChannel chan struct{}

	channel string
	message string
}

func NewSlackDash(token, ifname string, addr net.HardwareAddr, ch, msg string) *SlackDash {
	return &SlackDash{
		client:   slack.New(token),
		ifname:   ifname,
		dashAddr: addr,
		channel:  ch,
		message:  msg,
	}
}

func (d *SlackDash) Start() error {
	iface, err := net.InterfaceByName(d.ifname)
	if err != nil {
		return err
	}
	d.iface = iface

	handle, err := d.open()
	if err != nil {
		return err
	}
	defer handle.Close()

	d.stopChannel = make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)

	go d.readARP(handle, &wg)

	wg.Wait()

	return nil
}

func (d *SlackDash) Stop() {
	close(d.stopChannel)
}

func (d *SlackDash) open() (*pcap.Handle, error) {
	iface := d.iface

	var addr *net.IPNet
	if addrs, err := iface.Addrs(); err != nil {
		return nil, err
	} else {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					addr = &net.IPNet{
						IP:   ip4,
						Mask: ipnet.Mask[len(ipnet.Mask)-4:],
					}
					break
				}
			}
		}
	}

	if addr == nil {
		return nil, errors.New("no good IP network found")
	} else if addr.IP[0] == 127 {
		return nil, errors.New("skipping localhost")
	} else if addr.Mask[0] != 0xff || addr.Mask[1] != 0xff {
		return nil, errors.New("mask means network is to large")
	}
	log.Printf("Using network range %v for interface %v", addr, iface.Name)

	return pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
}

func (d *SlackDash) readARP(handle *pcap.Handle, wg *sync.WaitGroup) {
	defer wg.Done()

	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-d.stopChannel:
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)

			if arp.Operation == layers.ARPRequest && bytes.Equal(arp.SourceHwAddress, d.dashAddr) {
				// arp request

				// PostMessage
				d.postMessage()
			}
		}
	}
}

func (d *SlackDash) postMessage() {
	params := slack.NewPostMessageParameters()
	params.AsUser = true
	_, _, err := d.client.PostMessage(d.channel, d.message, params)
	if err != nil {
		log.Printf("[ERROR] %s", err)
	} else {
		log.Println("Message posted.")
	}
}

func init() {
	flag.StringVar(&slackAPIToken, "token", os.Getenv("SLACK_API_TOKEN"), "Slack API token.")
	flag.StringVar(&dashButtonMACAddr, "dash-addr", os.Getenv("DASH_BUTTON_MAC_ADDR"), "MAC address of Dash Button.")
}

func main() {
	flag.Parse()

	if flag.NArg() < 3 {
		flag.PrintDefaults()
		os.Exit(1)
	}

	ifname := flag.Arg(0)
	ch := flag.Arg(1)
	msg := flag.Arg(2)

	addr, err := net.ParseMAC(dashButtonMACAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	dash := NewSlackDash(slackAPIToken, ifname, addr, ch, msg)

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer close(sig)

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
