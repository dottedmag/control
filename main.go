package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/exp/maps"
)

var nss = []string{"8.8.8.8:53", "1.1.1.1:53"}

var failed atomic.Bool

func query(client *dns.Client, ns string, name string, queryType string) (*dns.Msg, error) {
	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{
			{Name: dns.Fqdn(name), Qtype: dns.StringToType[queryType], Qclass: dns.ClassINET},
		},
	}
	resp, _, err := client.Exchange(m, ns)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("empty response")
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("non-success response %s", dns.RcodeToString[resp.Rcode])
	}
	return resp, nil
}

func checkARecord(actualRecords []dns.RR, expectedRecords []record) error {
	expectedValues := map[string]bool{}
	for _, expectedValue := range expectedRecords {
		expectedValues[expectedValue.Target] = true
	}

	actualValues := map[string]bool{}
	for i := 0; i < len(expectedValues); i++ {
		a, ok := actualRecords[i].(*dns.A)
		if !ok {
			return fmt.Errorf("expected A record, got %s", dns.TypeToString[actualRecords[i].Header().Rrtype])
		}
		actualValues[a.A.String()] = true
	}

	if !maps.Equal(expectedValues, actualValues) {
		return fmt.Errorf("expected values %v, got %v", expectedValues, actualValues)
	}
	return nil
}

func checkAAAARecord(actualRecords []dns.RR, expectedRecords []record) error {
	expectedValues := map[string]bool{}

	for _, expectedValue := range expectedRecords {
		expectedValues[expectedValue.Target] = true
	}

	actualValues := map[string]bool{}
	for i := 0; i < len(expectedValues); i++ {
		aaaa, ok := actualRecords[i].(*dns.AAAA)
		if !ok {
			return fmt.Errorf("expected AAAA record, got %s", dns.TypeToString[actualRecords[i].Header().Rrtype])
		}
		actualValues[aaaa.AAAA.String()] = true
	}

	if !maps.Equal(expectedValues, actualValues) {
		return fmt.Errorf("expected values %v, got %v", expectedValues, actualValues)
	}
	return nil
}

func checkCNAMERecord(actualRecords []dns.RR, expectedRecords []record) error {
	expectedValues := map[string]bool{}

	for _, expectedValue := range expectedRecords {
		expectedValues[expectedValue.Target] = true
	}

	actualValues := map[string]bool{}
	for i := 0; i < len(expectedValues); i++ {
		cname, ok := actualRecords[i].(*dns.CNAME)
		if !ok {
			return fmt.Errorf("expected CNAME record, got %s", dns.TypeToString[actualRecords[i].Header().Rrtype])
		}
		actualValues[cname.Target] = true
	}

	if !maps.Equal(expectedValues, actualValues) {
		return fmt.Errorf("expected values %v, got %v", expectedValues, actualValues)
	}
	return nil
}

func checkCAARecord(actualRecords []dns.RR, expectedRecords []record) error {
	type caa struct {
		tag   string
		value string
	}
	expectedValues := map[caa]bool{}

	for _, expectedValue := range expectedRecords {
		expectedValues[caa{
			tag:   expectedValue.CAATag,
			value: expectedValue.Target,
		}] = true
	}

	actualValues := map[caa]bool{}
	for i := 0; i < len(expectedValues); i++ {
		caaRec, ok := actualRecords[i].(*dns.CAA)
		if !ok {
			return fmt.Errorf("expected CAA record, got %s", dns.TypeToString[actualRecords[i].Header().Rrtype])
		}
		actualValues[caa{
			tag:   caaRec.Tag,
			value: caaRec.Value,
		}] = true
	}

	if !maps.Equal(expectedValues, actualValues) {
		return fmt.Errorf("expected values %v, got %v", expectedValues, actualValues)
	}
	return nil
}

func checkMXRecord(actualRecords []dns.RR, expectedRecords []record) error {
	type mx struct {
		preference int
		value      string
	}
	expectedValues := map[mx]bool{}

	for _, expectedValue := range expectedRecords {
		expectedValues[mx{
			preference: expectedValue.MXPreference,
			value:      expectedValue.Target,
		}] = true
	}

	actualValues := map[mx]bool{}
	for i := 0; i < len(expectedValues); i++ {
		mxRec, ok := actualRecords[i].(*dns.MX)
		if !ok {
			return fmt.Errorf("expected MX record, got %s", dns.TypeToString[actualRecords[i].Header().Rrtype])
		}
		actualValues[mx{
			preference: int(mxRec.Preference),
			value:      mxRec.Mx,
		}] = true
	}

	if !maps.Equal(expectedValues, actualValues) {
		return fmt.Errorf("expected values %v, got %v", expectedValues, actualValues)
	}
	return nil
}

func checkTXTRecord(actualRecords []dns.RR, expectedRecords []record) error {
	expectedValues := map[string]bool{}

	for _, expectedValue := range expectedRecords {
		expectedValues[strings.Join(expectedValue.TXTStrings, "\x00")] = true
	}

	actualValues := map[string]bool{}
	for i := 0; i < len(expectedValues); i++ {
		txtRec, ok := actualRecords[i].(*dns.TXT)
		if !ok {
			return fmt.Errorf("expected TXT record, got %s", dns.TypeToString[actualRecords[i].Header().Rrtype])
		}
		actualValues[strings.Join(txtRec.Txt, "\x00")] = true
	}

	if !maps.Equal(expectedValues, actualValues) {
		return fmt.Errorf("expected values %v, got %v", expectedValues, actualValues)
	}
	return nil
}

type record struct {
	Type         string
	Name         string
	TTL          int
	Target       string
	CAATag       string
	MXPreference int
	TXTStrings   []string
}

func absolutize(domain string, rel string) string {
	if rel == "@" {
		return domain
	}

	return rel + "." + domain
}

func doCheckRecord(ns string, domain string, name string, records []record) error {
	recordType := records[0].Type

	client := &dns.Client{}
	resp, err := query(client, ns, name, recordType)
	if err != nil {
		return err
	}

	if len(records) != len(resp.Answer) {
		return fmt.Errorf("expected %d records, got %d", len(records), len(resp.Answer))
	}

	for _, answer := range resp.Answer {
		if answer.Header().Ttl > uint32(records[0].TTL) {
			return fmt.Errorf("expected ttl %d, got %d", records[0].TTL, answer.Header().Ttl)
		}
	}

	switch recordType {
	case "A":
		return checkARecord(resp.Answer, records)
	case "AAAA":
		return checkAAAARecord(resp.Answer, records)
	case "CNAME":
		return checkCNAMERecord(resp.Answer, records)
	case "CAA":
		return checkCAARecord(resp.Answer, records)
	case "MX":
		return checkMXRecord(resp.Answer, records)
	case "TXT":
		return checkTXTRecord(resp.Answer, records)
	default:
		return fmt.Errorf("unknown record type")
	}
}

func checkRecord(wg *sync.WaitGroup, ns string, domain string, records []record) {
	defer wg.Done()

	absoluteName := absolutize(domain, records[0].Name)

	if err := doCheckRecord(ns, domain, absoluteName, records); err != nil {
		fmt.Fprintf(os.Stderr, "\n%s %s (at %s): %v\n", records[0].Type, absoluteName, ns, err)
		failed.Store(true)
	} else {
		fmt.Print(".")
	}
}

func main() {
	records, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read stdin: %v\n", err)
		os.Exit(1)
	}

	var data struct {
		Domains []struct {
			Name    string
			Records []record
		}
	}

	if err := json.Unmarshal(records, &data); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse DNSControl output: %v\n", err)
		os.Exit(1)
	}

	wg := &sync.WaitGroup{}

	for _, domain := range data.Domains {
		type nameType struct {
			name string
			typ  string
		}

		recordsByNameType := map[nameType][]record{}
		for _, record := range domain.Records {
			nt := nameType{name: record.Name, typ: record.Type}
			recordsByNameType[nt] = append(recordsByNameType[nt], record)
		}

		for _, records := range recordsByNameType {
			for _, ns := range nss {
				wg.Add(1)
				time.Sleep(10 * time.Millisecond) // To avoid hitting rate-limits
				go checkRecord(wg, ns, domain.Name, records)
			}
		}
	}

	wg.Wait()

	if failed.Load() {
		os.Exit(1)
	}

	fmt.Println("\nAll checks passed")
}
