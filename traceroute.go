package main

// https://github.com/vaegt/go-traceroute/

import (
	"fmt"
	"net"
	"time"
	"errors"
	"math/rand"
	"os"
	"strconv"
	c "github.com/fatih/color"
	trace "github.com/pl0th/go-traceroute"
	"github.com/urfave/cli"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// TraceData represents data received by executing traceroute.
type TraceData struct {
	Hops    [][]Hop
	Dest    net.IP
	Timeout time.Duration
	Tries   int
	MaxTTL  int
	Port    int
	Proto   string
	IPv     string
}

// Hop represents a path between a source and a destination.
type Hop struct {
	TryNumber int
	TTL       int
	AddrIP    net.IP
	AddrDNS   []string //net.IPAddr
	Latency   time.Duration
	Err       error
}

// Exec returns TraceData with initialized Hops and inserts the IP version into the protocol
func Exec(dest net.IP, timeout time.Duration, tries int, maxTTL int, proto string, port int) (data TraceData) {
	data = TraceData{
		Hops:    make([][]Hop, tries),
		Dest:    dest,
		Timeout: timeout,
		Tries:   tries,
		MaxTTL:  maxTTL,
		Port:    port,
		Proto:   proto,
	}
	if dest.To4() == nil {
		data.IPv = "6"
	} else {
		data.IPv = "4"
	}
	return
}

// Next executes the doHop method for every try.
func (data *TraceData) Next() (err error) {
	ttl := len(data.Hops[0]) + 1
	if ttl > data.MaxTTL {
		return errors.New("Maximum TTL reached")
	}
	for try := 0; try < data.Tries; try++ {
		currentHop, err := doHop(ttl, data.Dest, data.Timeout, data.Proto, data.Port, data.IPv)
		if err != nil {
			return err
		}
		if currentHop.Err == nil {
			currentHop.AddrDNS, _ = net.LookupAddr(currentHop.AddrIP.String()) // maybe use memoization
		}
		currentHop.TryNumber = try
		data.Hops[try] = append(data.Hops[try], currentHop)
	}
	return
}

func doHop(ttl int, dest net.IP, timeout time.Duration, proto string, port int, ipv string) (currentHop Hop, err error) {
	var destString string
	if port == 0 {
		destString = dest.String()
	} else {
		destString = dest.String() + ":" + strconv.Itoa(port)
	}
	req := []byte{}
	dialProto := proto

	if proto == "udp" {
		req = []byte("TABS")
		dialProto += ipv
	} else if proto == "icmp" {
		dialProto = "ip" + ipv + ":" + proto
	} else {
		return currentHop, errors.New("protocol not implemented")
	}

	conn, err := net.Dial(dialProto, destString)
	if err != nil {
		return
	}
	defer conn.Close()

	listenAddress := "0.0.0.0"

	if ipv == "4" {
		newConn := ipv4.NewConn(conn)
		if err = newConn.SetTTL(ttl); err != nil {
			return
		}
		if proto == "icmp" {
			req, err = createICMPEcho(ipv4.ICMPTypeEcho)
			if err != nil {
				return
			}
		}
	} else if ipv == "6" {
		listenAddress = "::0"
		newConn := ipv6.NewConn(conn)
		if err = newConn.SetHopLimit(ttl); err != nil {
			return
		}
		if proto == "icmp" {
			req, err = createICMPEcho(ipv6.ICMPTypeEchoRequest)
			if err != nil {
				return
			}
		}
	}

	packetConn, err := icmp.ListenPacket("ip"+ipv+":"+"icmp", listenAddress)
	if err != nil {
		return
	}
	defer packetConn.Close()

	start := time.Now()
	_, err = conn.Write(req)

	if err != nil {
		return
	}
	if err = packetConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return
	}

	readBytes := make([]byte, 1500)                     // 1500 Bytes ethernet MTU
	_, sAddr, connErr := packetConn.ReadFrom(readBytes) // first return value (Code) might be useful

	latency := time.Since(start)

	currentHop = Hop{
		TTL:     ttl,
		Latency: latency,
		Err:     connErr,
	}

	if connErr == nil {
		currentHop.AddrIP = net.ParseIP(sAddr.String())
		if currentHop.AddrIP == nil {
			currentHop.Err = errors.New("timeout reached")
		}
	}

	return currentHop, err
}

// All executes all doHops for all tries.
func (data *TraceData) All() (err error) {
	for try := 0; try < data.Tries; try++ {
		for ttl := 1; ttl <= data.MaxTTL; ttl++ {
			currentHop, err := doHop(ttl, data.Dest, data.Timeout, data.Proto, data.Port, data.IPv)
			if err != nil {
				return err
			}
			if currentHop.Err == nil {
				currentHop.AddrDNS, _ = net.LookupAddr(currentHop.AddrIP.String()) // maybe use memoization
			}
			currentHop.TryNumber = try
			data.Hops[try] = append(data.Hops[try], currentHop)
			if currentHop.Err == nil && data.Dest.Equal(currentHop.AddrIP) {
				break
			}
		}
	}
	return
}

func createICMPEcho(ICMPTypeEcho icmp.Type) (req []byte, err error) {
	echo := icmp.Message{
		Type: ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID:   rand.Int(),
			Seq:  1, // TODO Sequence should be incremented every Hop & the id should be changed on every try(not random but different)
			Data: []byte("TABS"),
		}}

	req, err = echo.Marshal(nil)
	return
}

func MainTraceroute() {
	app := cli.NewApp()
	app.Version = "0.1"
	app.Name = "go-traceroute"
	app.Usage = "A coloured traceroute implemented in golang"
	app.Flags = []cli.Flag{
		cli.IntFlag{
			Name:  "ttl, T",
			Value: 64,
			Usage: "sets the max. TTL value",
		},
		cli.Float64Flag{
			Name:  "timeout, o",
			Value: 3,
			Usage: "sets the timeout for the icmp echo request in seconds",
		},
		cli.IntFlag{
			Name:  "tries, t",
			Value: 3,
			Usage: "sets the amount of tries",
		},
		cli.StringFlag{
			Name:  "protocol, P",
			Value: "icmp",
			Usage: "sets the request protocol",
		},
		cli.IntFlag{
			Name:  "port, p",
			Value: 33434,
			Usage: "sets the port for udp requests",
		},
		cli.BoolFlag{
			Name:        "colour, c",
			Usage:       "disables colour",
			Destination: &c.NoColor,
		},
	}

	app.Action = func(ctx *cli.Context) (err error) {
		if len(ctx.Args()) == 0 {
			cli.ShowAppHelp(ctx)
			return
		}

		ip := net.ParseIP(ctx.Args()[0])

		if ip == nil {
			ips, err := net.LookupIP(ctx.Args()[0])
			if err != nil || len(ips) == 0 {
				c.Yellow("Please provide a valid IP address or fqdn")
				return cli.NewExitError(errors.New(c.RedString("Error: %v", err.Error())), 137)
			}
			ip = ips[0]
		}
		traceData := trace.TraceData{}
		if ctx.String("protocol") == "udp" {
			traceData = trace.Exec(ip, time.Duration(ctx.Float64("timeout")*float64(time.Second.Nanoseconds())), ctx.Int("tries"), ctx.Int("ttl"), ctx.String("protocol"), ctx.Int("port"))
		} else {
			traceData = trace.Exec(ip, time.Duration(ctx.Float64("timeout")*float64(time.Second.Nanoseconds())), ctx.Int("tries"), ctx.Int("ttl"), ctx.String("protocol"), 0)
		}

		hops := make([][]printData, 0)
		err = traceData.Next()
	Loop:
		for idxTry := 0; err == nil; err = traceData.Next() {
			usedIPs := make(map[string][]time.Duration)
			hops = append(hops, make([]printData, 0))
			for idx := 0; idx < traceData.Tries; idx++ {
				hop := traceData.Hops[idx][len(hops)-1]
				if len(hop.AddrDNS) == 0 {
					traceData.Hops[idx][len(hops)-1].AddrDNS = append(hop.AddrDNS, "no dns entry found")
				}

				usedIPs[hop.AddrIP.String()] = append(usedIPs[hop.AddrIP.String()], hop.Latency)
				hops[len(hops)-1] = append(hops[len(hops)-1], printData{[]time.Duration{hop.Latency}, 1, hop})
			}
			for idx := 0; idx < traceData.Tries; idx++ {
				hop := traceData.Hops[idx][len(hops)-1]
				if _, ok := usedIPs[hop.AddrIP.String()]; ok {
					addrString := fmt.Sprintf("%v (%v) ", c.YellowString(hop.AddrIP.String()), c.CyanString(hop.AddrDNS[0]))
					if hop.AddrIP == nil {
						addrString = c.RedString("no response ")
					}

					fmt.Printf("%v: %v", idxTry, addrString)
					for _, lat := range usedIPs[hop.AddrIP.String()] {
						latString, formString := lat.String(), ""
						if lat > time.Second {
							formString = fmt.Sprintf("%v ", latString[:4]+latString[len(latString)-1:])
						} else if lat < time.Millisecond && lat > time.Nanosecond {
							formString = fmt.Sprintf("%v ", latString[:4]+latString[len(latString)-3:])
						} else {
							formString = fmt.Sprintf("%v ", latString[:4]+latString[len(latString)-2:])
						}
						fmt.Printf(c.MagentaString(formString)) //µs
					}
					fmt.Println()
				}
				delete(usedIPs, hop.AddrIP.String())
				if traceData.Dest.Equal(hop.AddrIP) && traceData.Tries == idx+1 {
					break Loop
				}
			}
			idxTry++
		}
		if err != nil {
			c.Yellow("Please make sure you run this command as root")
			return cli.NewExitError(errors.New(c.RedString("Error: %v", err.Error())), 137)
		}

		return
	}

	app.Run(os.Args)

}

type printData struct {
	latencies []time.Duration
	count     int
	trace.Hop
}

func main() {
	MainTraceroute()
}