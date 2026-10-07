package osp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"time"
)

// How many tests the engine has loaded. OSP cannot say: ospd-openvas keeps
// its tests in redis, so the "total" attribute of get_vts is always empty,
// a filter that would select nothing is refused, and the full listing is
// 170 MB and takes 36 s (measured on 22.10.5 with the Community Feed). The
// engine's own source is asked instead: one "nvt:<oid>" key per test in the
// redis database that holds the key "nvticache".

// DefaultRedisSocket is where install-openvas.sh puts the engine's redis.
const DefaultRedisSocket = "/run/redis-openvas/redis.sock"

// errNoVTCache: no database holds the engine's test cache (yet).
var errNoVTCache = errors.New("redis: no nvticache database")

// maxRedisDBs bounds the databases looked at for the cache. openvas takes
// the first free one when it loads the feed, so it is among the lowest.
const maxRedisDBs = 32

// countVTs counts the tests in the engine's redis.
func countVTs(ctx context.Context, sock string) (int, error) {
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "unix", sock)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	deadline := time.Now().Add(15 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	rc := &resp{r: bufio.NewReaderSize(conn, 1<<16), w: conn}

	// Database 0 holds the index of the databases in use.
	dbs := []int{1}
	if v, err := rc.do("HKEYS", "GVM.__GlobalDBIndex"); err == nil {
		if list, ok := v.([]any); ok {
			dbs = dbs[:0]
			for _, x := range list {
				if s, ok := x.(string); ok {
					if n, err := strconv.Atoi(s); err == nil && n > 0 {
						dbs = append(dbs, n)
					}
				}
			}
			sort.Ints(dbs)
		}
	}
	if len(dbs) > maxRedisDBs {
		dbs = dbs[:maxRedisDBs]
	}
	for _, db := range dbs {
		if _, err := rc.do("SELECT", strconv.Itoa(db)); err != nil {
			return 0, err
		}
		v, err := rc.do("EXISTS", "nvticache")
		if err != nil {
			return 0, err
		}
		if n, _ := v.(int64); n == 0 {
			continue
		}
		total, cursor := 0, "0"
		for {
			v, err := rc.do("SCAN", cursor, "MATCH", "nvt:*", "COUNT", "20000")
			if err != nil {
				return 0, err
			}
			page, ok := v.([]any)
			if !ok || len(page) != 2 {
				return 0, errors.New("redis: unexpected SCAN reply")
			}
			keys, _ := page[1].([]any)
			total += len(keys)
			if cursor, _ = page[0].(string); cursor == "0" || cursor == "" {
				return total, nil
			}
		}
	}
	return 0, errNoVTCache
}

// resp is the little of the redis protocol the count needs.
type resp struct {
	r *bufio.Reader
	w io.Writer
}

func (c *resp) do(args ...string) (any, error) {
	buf := []byte("*" + strconv.Itoa(len(args)) + "\r\n")
	for _, a := range args {
		buf = append(buf, "$"+strconv.Itoa(len(a))+"\r\n"+a+"\r\n"...)
	}
	if _, err := c.w.Write(buf); err != nil {
		return nil, err
	}
	return c.read(0)
}

func (c *resp) read(depth int) (any, error) {
	line, err := c.r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if len(line) < 3 || line[len(line)-2] != '\r' {
		return nil, errors.New("redis: malformed reply")
	}
	kind, text := line[0], line[1:len(line)-2]
	switch kind {
	case '+':
		return text, nil
	case '-':
		return nil, fmt.Errorf("redis: %s", text)
	case ':':
		return strconv.ParseInt(text, 10, 64)
	case '$':
		n, err := strconv.Atoi(text)
		if err != nil || n > 1<<20 {
			return nil, errors.New("redis: bad bulk length")
		}
		if n < 0 {
			return nil, nil
		}
		b := make([]byte, n+2)
		if _, err := io.ReadFull(c.r, b); err != nil {
			return nil, err
		}
		return string(b[:n]), nil
	case '*':
		n, err := strconv.Atoi(text)
		if err != nil || n > 1<<20 || depth > 2 {
			return nil, errors.New("redis: bad array")
		}
		if n < 0 {
			return nil, nil
		}
		out := make([]any, 0, n)
		for i := 0; i < n; i++ {
			v, err := c.read(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	}
	return nil, errors.New("redis: unknown reply type")
}
