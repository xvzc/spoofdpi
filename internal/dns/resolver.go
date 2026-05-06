package dns

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"sync"

	"github.com/miekg/dns"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/dns/addrselect"
)

type Resolver interface {
	Resolve(ctx context.Context, domain string, rule *config.Rule) (*RecordSet, error)
}

type exchangeFunc = func(
	ctx context.Context,
	msg *dns.Msg,
	upstream string,
) (*dns.Msg, error)

type msgChan struct {
	msg *dns.Msg
	err error
}

type RecordSet struct {
	Addrs []net.IP
	TTL   uint32
}

func (rs *RecordSet) Clone() *RecordSet {
	return &RecordSet{
		Addrs: append([]net.IP(nil), rs.Addrs...),
		TTL:   rs.TTL,
	}
}

func parseQueryTypes(qtype config.DNSQueryType) []uint16 {
	switch qtype {
	case config.DNSQueryIPv4:
		return []uint16{dns.TypeA}
	case config.DNSQueryIPv6:
		return []uint16{dns.TypeAAAA}
	case config.DNSQueryAll:
		return []uint16{dns.TypeA, dns.TypeAAAA}
	default:
		return []uint16{dns.TypeA}
	}
}

func newMsg(domain string, qType uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qType)

	return msg
}

func recordTypeIDToName(id uint16) string {
	switch id {
	case dns.TypeA:
		return "A"
	case dns.TypeAAAA:
		return "AAAA"
	}

	return strconv.FormatUint(uint64(id), 10)
}

func lookupType(
	ctx context.Context,
	domain string,
	upstream string,
	queryType uint16,
	exchange exchangeFunc,
) *msgChan {
	resMsg, err := exchange(ctx, newMsg(domain, queryType), upstream)
	if err != nil {
		queryName := recordTypeIDToName(queryType)
		err = fmt.Errorf(
			"failed to resolve '%s', query type=%s: %w",
			domain,
			queryName,
			err,
		)

		return &msgChan{msg: nil, err: err}
	}

	return &msgChan{msg: resMsg, err: nil}
}

func lookupAllTypes(
	ctx context.Context,
	domain string,
	upstream string,
	qTypes []uint16,
	exchange exchangeFunc,
) <-chan *msgChan {
	var wg sync.WaitGroup
	resCh := make(chan *msgChan)

	for _, qType := range qTypes {
		wg.Add(1)

		go func(qType uint16) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			case resCh <- lookupType(ctx, domain, upstream, qType, exchange):
			}
		}(qType)
	}

	go func() {
		wg.Wait()
		close(resCh)
	}()

	return resCh
}

func parseMsg(msg *dns.Msg) ([]net.IP, uint32, bool) {
	var addrs []net.IP
	minTTL := uint32(math.MaxUint32)
	ok := false

	for _, record := range msg.Answer {
		switch ipRecord := record.(type) {
		case *dns.A:
			ok = true
			addrs = append(addrs, ipRecord.A)
			minTTL = min(minTTL, record.Header().Ttl)
		case *dns.AAAA:
			ok = true
			addrs = append(addrs, ipRecord.AAAA)
			minTTL = min(minTTL, record.Header().Ttl)
		}
	}

	return addrs, minTTL, ok
}

func processMessages(
	ctx context.Context,
	resCh <-chan *msgChan,
) (*RecordSet, error) {
	var errs []error
	var addrs []net.IP

	minTTL := uint32(math.MaxUint32)
	found := false

loop: // Loop until the channel is closed or context is canceled
	for {
		select {
		// Detect context cancellation immediately to prevent blocking
		case <-ctx.Done():
			return nil, ctx.Err()

		case result, ok := <-resCh:
			// If the channel is closed, break the loop
			if !ok {
				break loop
			}

			if result.err != nil {
				errs = append(errs, result.err)
				continue
			}

			// Defensive check for nil msg
			if result.msg == nil {
				continue
			}

			resultAddrs, ttl, ok := parseMsg(result.msg)
			if ok {
				addrs = append(addrs, resultAddrs...)
				minTTL = min(minTTL, ttl)
				found = true
			}
		}
	}

	// If we found any valid addresses,
	// return them even if some errors occurred (Partial Success)
	if len(addrs) > 0 {
		if !found {
			minTTL = 0
		}
		addrselect.SortByRFC6724(addrs)
		return &RecordSet{Addrs: addrs, TTL: minTTL}, nil
	}

	// Only return errors if no addresses were found at all
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return nil, fmt.Errorf("record not found")
}
