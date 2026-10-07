package osptest

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// The engine's redis, as far as the daemon talks to it: database 1 holds
// the test cache, one "nvt:<oid>" key per test, next to the key
// "nvticache" once a feed is loaded. That is where the real ospd-openvas
// keeps its tests and the only place their number can be read.

// scanPage is how many keys one SCAN call of the fake returns at most.
const scanPage = 20000

func (f *Fake) serveRedis(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	db := 0
	for {
		args, err := readCommand(r)
		if err != nil || len(args) == 0 {
			return
		}
		var reply string
		switch strings.ToUpper(args[0]) {
		case "HKEYS":
			reply = "*1\r\n$1\r\n1\r\n"
		case "SELECT":
			db, _ = strconv.Atoi(arg(args, 1))
			reply = "+OK\r\n"
		case "EXISTS":
			reply = ":0\r\n"
			if db == 1 && arg(args, 1) == "nvticache" && f.version() != "" {
				reply = ":1\r\n"
			}
		case "SCAN":
			start, _ := strconv.Atoi(arg(args, 1))
			total := 0
			if db == 1 && f.version() != "" {
				total = f.vtCount()
			}
			end := min(start+scanPage, total)
			next := "0"
			if end < total {
				next = strconv.Itoa(end)
			}
			var sb strings.Builder
			fmt.Fprintf(&sb, "*2\r\n$%d\r\n%s\r\n*%d\r\n", len(next), next, max(end-start, 0))
			for i := start; i < end; i++ {
				k := "nvt:1.3.6.1.4.1.25623.1.0." + strconv.Itoa(i)
				fmt.Fprintf(&sb, "$%d\r\n%s\r\n", len(k), k)
			}
			reply = sb.String()
		default:
			reply = "-ERR unknown command\r\n"
		}
		if _, err := io.WriteString(c, reply); err != nil {
			return
		}
	}
}

func arg(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return ""
}

// readCommand reads one RESP array of bulk strings.
func readCommand(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "*")))
	if err != nil || n < 0 || n > 64 {
		return nil, fmt.Errorf("bad command header %q", line)
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		l, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "$")))
		if err != nil || l < 0 || l > 1<<16 {
			return nil, fmt.Errorf("bad bulk header %q", line)
		}
		b := make([]byte, l+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		out = append(out, string(b[:l]))
	}
	return out, nil
}
