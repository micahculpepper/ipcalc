package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// TwoFiveFive = 255.255.255.255
var TwoFiveFive uint32 = 4294967295

// Ipv4 represents the properties of an Ipv4 address/network using 32-bit unsigned integers.
type Ipv4 struct {
	Host      uint32
	Mask      uint32
	Network   uint32
	Broadcast uint32
}

func (i *Ipv4) setNetwork() {
	i.Network = i.Mask + i.Host - (i.Mask | i.Host)
}

func (i *Ipv4) setBroadcast() {
	i.Broadcast = TwoFiveFive - i.Mask + i.Network
}

// CidrToIpv4 converts takes a string in CIDR format and returns an Ipv4 type.
// If the input string has no "/", it assumes a "/32" mask is intended.
func CidrToIpv4(c string) (Ipv4, error) {
	var res Ipv4

	cidrArr := strings.Split(c, "/")

	h, err := stringToHost(cidrArr[0])
	if err != nil {
		return res, errors.New("Failed to convert CIDR string to bits")
	}
	res.Host = h

	if len(cidrArr) == 2 {
		m, err := stringToMask(cidrArr[1])
		if err != nil {
			return res, errors.New("Failed to convert CIDR string to bits")
		}
		res.Mask = m
	} else {
		res.Mask = TwoFiveFive
	}
	res.setNetwork()
	res.setBroadcast()
	return res, nil
}

// Convert Ipv4 dotted decimal string to 32-bit binary
func stringToHost(s string) (uint32, error) {
	octets := strings.Split(s, ".")
	var host []byte

	for _, b := range octets {
		n, err := strconv.Atoi(b)
		if (err != nil) || (n < 0) || (n > 255) {
			return 0, errors.New("Failed to convert dotted decimal to bits")
		}
		host = append(host, byte(n))
	}

	if len(host) != 4 {
		return 0, errors.New("Failed to convert dotted decimal to bits")
	}

	buf := bytes.NewReader(host)
	var res uint32
	err := binary.Read(buf, binary.BigEndian, &res)
	if err != nil {
		return 0, errors.New("Failed to convert dotted decimal to bits")
	}
	return res, nil
}

// Convert CIDR prefix length string (without the "/") to bitmask
func stringToMask(s string) (uint32, error) {
	n, err := strconv.Atoi(s)
	if (err != nil) || (n < 0) || (n > 32) {
		return 0, errors.New("Invalid CIDR prefix")
	}
	b := byte(n)
	return TwoFiveFive - uint32((1<<(32-b))-1), nil
}

// ToCidr returns a string representation of an Ipv4 object in CIDR format.
// Discontiguous subnet masks will produce undefined results.
func (i *Ipv4) ToCidr() string {
	h := hostToString(i.Host)
	m := maskToString(i.Mask)
	return strings.Join([]string{h, m}, "/")
}

func hostToString(n uint32) string {
	a := make([]byte, 4)
	binary.BigEndian.PutUint32(a, n)
	w := []string{}
	for _, b := range a {
		s := strconv.Itoa(int(b))
		w = append(w, s)
	}
	return strings.Join(w, ".")
}

func maskToString(m uint32) string {
	for i := 0; i <= 32; i++ {
		if m == TwoFiveFive {
			return strconv.Itoa(32 - i)
		}
		m = uint32(1)<<31 + m>>1
	}

	return "0"
}

// IsInNet returns true if all of n1 falls within the bounds of n2.
func IsInNet(n1 Ipv4, n2 Ipv4) bool {
	if (n1.Host >= n2.Host) && (n1.Broadcast <= n2.Broadcast) {
		return true
	}
	return false
}

// Overlap returns a slice of the networks shared by networks n1 and n2.
func Overlap(n1 Ipv4, n2 Ipv4) []Ipv4 {
	var lo Ipv4
	var hi Ipv4

	switch {
	case n1.Host < n2.Host:
		lo = n1
		hi = n2
	case n1.Host > n2.Host:
		hi = n1
		lo = n2
	case n1.Host == n2.Host:
		switch {
		case n1.Mask > n2.Mask:
			lo = n1
			hi = n2
		case n1.Mask < n2.Mask:
			hi = n1
			lo = n2
		case n1 == n2:
			return []Ipv4{n1}
		}
	}

	var start uint32
	var stop uint32
	start = hi.Host
	if lo.Broadcast < hi.Broadcast {
		stop = lo.Broadcast
	} else {
		stop = hi.Broadcast
	}

	if (stop < start) || (start > lo.Broadcast) {
		return []Ipv4{}
	}

	res, err := Subnet(start, stop)
	if err != nil {
		return []Ipv4{}
	}
	return res
}

// Subnet summarizes a range of IP addresses defined by uint32 bounds into
// the smallest possible amount of subnets (largest possible network sizes).
func Subnet(start uint32, stop uint32) ([]Ipv4, error) {
	fmt.Printf("Subnetting %v to %v\n", start, stop)
	if start == stop {
		return []Ipv4{{Host: start,
			Mask:      TwoFiveFive,
			Network:   start,
			Broadcast: start}}, nil
	}

	if start > stop {
		return []Ipv4{}, errors.New("Argument order is backwards")
	}

	var lo Ipv4
	lo.Host = start
	sharedBits := start ^ stop
	for bits := uint(0); bits <= 32; bits++ {
		if sharedBits>>bits == 0 {
			lo.Mask = TwoFiveFive - (uint32(1)<<bits - 1)
			break
		}
	}
	for {
		lo.setNetwork()
		if lo.Network == lo.Host {
			break
		}
		lo.Mask = uint32(1)<<31 + lo.Mask>>1
	}
	lo.setBroadcast()

	res := []Ipv4{lo}

	if lo.Broadcast == stop {
		return res, nil
	}
	if lo.Broadcast > stop {
		return res, errors.New("Internal Error")
	}

	next, err := Subnet(lo.Broadcast+1, stop)
	if err != nil {
		return res, err
	}
	res = append(res, next...)
	return res, nil
}

func main() {
	a, _ := CidrToIpv4("10.10.20.0/21")
	b, _ := CidrToIpv4("10.10.20.0/24")
	s := Overlap(a, b)
	for _, i := range s {
		fmt.Println(i.ToCidr())
	}
}
