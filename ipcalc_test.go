package ipcalc

import (
	"testing"
)

func TestConv(t *testing.T) {
	cidr := "10.244.170.8/28"
	ip := Ipv4{Host: 183806472, Mask: 4294967280}

	t.Log("Testing string conversion.")
	{
		t.Logf("\tTest 0: string to Ipv4")
		{
			resp, err := CidrToIpv4(cidr)
			if err != nil {
				t.Fatalf("\tError on conversion : %v", err)
			}
			if resp != ip {
				t.Fatalf("\tConversion produced the wrong answer : %v", resp)
			}
		}
		t.Logf("\tTest 1: Ipv4 to string")
		{
			resp := ip.ToCidr()
			if resp != cidr {
				t.Fatalf("\tConversion produced the wrong answer : %v", resp)
			}
		}
	}
}

func TestIsInNet(t *testing.T) {
	n1 := Ipv4{Host: 183806472, Mask: 4294967280}
	n2 := Ipv4{Host: 183806464, Mask: 4294967040}
	t.Log("Testing network containment detection.")
	{
		t.Logf("\tTest 0: 10.244.170.8/28 in 10.244.170.0/24")
		{
			res := IsInNet(n1, n2)
			if !res {
				t.Fatalf("\tTest produced the wrong answer; should be true.")
			}
		}
		t.Logf("\tTest 1: 10.244.170.0/24 in 10.244.170.8/28")
		{
			res := IsInNet(n2, n1)
			if res {
				t.Fatalf("\tTest produced the wrong answer; should be false.")
			}
		}
	}
}
