package dns

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"sync"

	"github.com/miekg/dns"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/dns/addrselect"
)

type exchangeFunc = func(
	ctx context.Context,
	msg *dns.Msg,
	upstream string,
) (*dns.Msg, error)

type msgChan struct {
	msg *dns.Msg
	err error
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

func parseMsg(msg *dns.Msg) ([]netip.Addr, uint32, bool) {
	var addrs []netip.Addr
	minTTL := uint32(math.MaxUint32)
	ok := false

	for _, record := range msg.Answer {
		switch ipRecord := record.(type) {
		case *dns.A:
			if a, valid := netip.AddrFromSlice(ipRecord.A); valid {
				ok = true
				addrs = append(addrs, a)
				minTTL = min(minTTL, record.Header().Ttl)
			}
		case *dns.AAAA:
			if a, valid := netip.AddrFromSlice(ipRecord.AAAA); valid {
				ok = true
				addrs = append(addrs, a)
				minTTL = min(minTTL, record.Header().Ttl)
			}
		}
	}

	return addrs, minTTL, ok
}

func processMessages(
	ctx context.Context,
	resCh <-chan *msgChan,
) ([]netip.Addr, uint32, error) {
	var errs []error
	var addrs []netip.Addr

	minTTL := uint32(math.MaxUint32)

loop:
	for {
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()

		case result, ok := <-resCh:
			if !ok {
				break loop
			}

			if result.err != nil {
				errs = append(errs, result.err)
				continue
			}

			if result.msg == nil {
				continue
			}

			resultAddrs, ttl, ok := parseMsg(result.msg)
			if ok {
				addrs = append(addrs, resultAddrs...)
				minTTL = min(minTTL, ttl)
			}
		}
	}

	if len(addrs) > 0 {
		addrselect.SortByRFC6724(addrs)
		return addrs, minTTL, nil
	}

	if len(errs) > 0 {
		return nil, 0, errors.Join(errs...)
	}

	return nil, 0, fmt.Errorf("record not found")
}
