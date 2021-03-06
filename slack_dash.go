package main

import (
	"bytes"
	"errors"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/nlopes/slack"
)

var arpInterval = 5 * time.Second

type SlackDash struct {
	client *slack.Client

	ifname   string
	iface    *net.Interface
	dashAddr net.HardwareAddr

	stopChannel chan struct{}

	channel string
	message string

	lastPost time.Time
}

func NewSlackDash(token, ifname string, addr net.HardwareAddr, ch, msg string) *SlackDash {
	return &SlackDash{
		client:      slack.New(token),
		ifname:      ifname,
		dashAddr:    addr,
		channel:     ch,
		message:     msg,
		stopChannel: make(chan struct{}),
		lastPost:    time.Now(),
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
				now := time.Now()
				// arp request
				if now.Sub(d.lastPost) >= arpInterval {
					// PostMessage
					d.postMessage()

					d.lastPost = now
				}
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
