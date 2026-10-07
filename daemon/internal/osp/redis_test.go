package osp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeRedis serves the commands the count uses. tests[db] is the number of
// nvt:* keys in a database; a database is the test cache when cache[db].
func fakeRedis(t *testing.T, index []string, cache map[int]bool, tests map[int]int, page int) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "rds-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := dir + "/redis.sock"
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				db := 0
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					n, _ := strconv.Atoi(strings.TrimSpace(line[1:]))
					args := make([]string, 0, n)
					for i := 0; i < n; i++ {
						h, _ := r.ReadString('\n')
						l, _ := strconv.Atoi(strings.TrimSpace(h[1:]))
						b := make([]byte, l+2)
						if _, err := io.ReadFull(r, b); err != nil {
							return
						}
						args = append(args, string(b[:l]))
					}
					var out strings.Builder
					switch args[0] {
					case "HKEYS":
						if index == nil {
							out.WriteString("-ERR no index\r\n")
							break
						}
						fmt.Fprintf(&out, "*%d\r\n", len(index))
						for _, k := range index {
							fmt.Fprintf(&out, "$%d\r\n%s\r\n", len(k), k)
						}
					case "SELECT":
						db, _ = strconv.Atoi(args[1])
						out.WriteString("+OK\r\n")
					case "EXISTS":
						if cache[db] {
							out.WriteString(":1\r\n")
						} else {
							out.WriteString(":0\r\n")
						}
					case "SCAN":
						start, _ := strconv.Atoi(args[1])
						end := min(start+page, tests[db])
						next := "0"
						if end < tests[db] {
							next = strconv.Itoa(end)
						}
						fmt.Fprintf(&out, "*2\r\n$%d\r\n%s\r\n*%d\r\n", len(next), next, end-start)
						for i := start; i < end; i++ {
							k := "nvt:" + strconv.Itoa(i)
							fmt.Fprintf(&out, "$%d\r\n%s\r\n", len(k), k)
						}
					default:
						out.WriteString("-ERR unknown\r\n")
					}
					if _, err := io.WriteString(c, out.String()); err != nil {
						return
					}
				}
			}()
		}
	}()
	return sock
}

func TestCountVTs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// The layout measured on the appliance: database 1 is the test cache,
	// the others are per-host knowledge bases. 95,103 tests, read in pages.
	sock := fakeRedis(t, []string{"1", "2", "3", "6"}, map[int]bool{1: true}, map[int]int{1: 95103, 2: 7}, 20000)
	if n, err := countVTs(ctx, sock); err != nil || n != 95103 {
		t.Fatalf("count = %d, %v", n, err)
	}
	// The cache is not always in database 1: it is the one with nvticache.
	sock = fakeRedis(t, []string{"4", "2", "9"}, map[int]bool{4: true}, map[int]int{2: 50, 4: 12}, 5)
	if n, err := countVTs(ctx, sock); err != nil || n != 12 {
		t.Fatalf("cache in database 4: count = %d, %v", n, err)
	}
	// No index to read: database 1 is still tried.
	sock = fakeRedis(t, nil, map[int]bool{1: true}, map[int]int{1: 3}, 20000)
	if n, err := countVTs(ctx, sock); err != nil || n != 3 {
		t.Fatalf("no index: count = %d, %v", n, err)
	}
	// A feed that is not loaded has no cache database, which is an error
	// and not a count of zero.
	sock = fakeRedis(t, []string{"1", "2"}, map[int]bool{}, map[int]int{1: 99}, 20000)
	if _, err := countVTs(ctx, sock); !errors.Is(err, errNoVTCache) {
		t.Fatalf("no cache database: %v", err)
	}
	if _, err := countVTs(ctx, sock+".missing"); err == nil {
		t.Fatal("a missing socket must be an error")
	}
}
