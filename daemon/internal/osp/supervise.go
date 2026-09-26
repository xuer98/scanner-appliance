package osp

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// Supervisor runs redis-openvas and ospd-openvas as children where there
// is no systemd (the container, PLAN §4.7). On the VM image the systemd
// units own them and the supervisor is not used.
type Supervisor struct {
	RedisConf string
	RedisSock string
	OSPD      string
	OSPDSock  string
	LogDir    string
	Log       *slog.Logger
}

// DefaultSupervisor matches install-openvas.sh's layout.
func DefaultSupervisor(log *slog.Logger) *Supervisor {
	return &Supervisor{RedisConf: "/etc/redis/redis-openvas.conf", RedisSock: "/run/redis-openvas/redis.sock",
		OSPD: "/opt/ospd/bin/ospd-openvas", OSPDSock: DefaultSocket, LogDir: "/var/log/gvm", Log: log}
}

// Available reports whether the engine binaries are installed.
func (s *Supervisor) Available() bool {
	_, err1 := exec.LookPath("redis-server")
	_, err2 := os.Stat(s.OSPD)
	_, err3 := os.Stat(s.RedisConf)
	return err1 == nil && err2 == nil && err3 == nil
}

// Run starts both processes and restarts them with backoff until ctx ends.
func (s *Supervisor) Run(ctx context.Context) {
	if s.Log == nil {
		s.Log = slog.Default()
	}
	for _, d := range []string{filepath.Dir(s.RedisSock), filepath.Dir(s.OSPDSock), s.LogDir, "/var/lib/openvas/redis"} {
		_ = os.MkdirAll(d, 0o755)
	}
	if u, err := user.Lookup("redis"); err == nil {
		uid, _ := strconv.Atoi(u.Uid)
		gid, _ := strconv.Atoi(u.Gid)
		_ = os.Chown(filepath.Dir(s.RedisSock), uid, gid)
		_ = os.Chown("/var/lib/openvas/redis", uid, gid)
	}
	go s.loop(ctx, "redis-openvas", func() *exec.Cmd {
		if os.Geteuid() == 0 {
			if _, err := user.Lookup("redis"); err == nil {
				return exec.Command("runuser", "-u", "redis", "--", "redis-server", s.RedisConf, "--daemonize", "no", "--supervised", "no")
			}
		}
		return exec.Command("redis-server", s.RedisConf, "--daemonize", "no", "--supervised", "no")
	})
	// ospd needs redis; wait for the socket before the first start.
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		if _, err := os.Stat(s.RedisSock); err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	s.loop(ctx, "ospd-openvas", func() *exec.Cmd {
		return exec.Command(s.OSPD, "--foreground", "--unix-socket", s.OSPDSock, "--socket-mode", "0o660",
			"--log-file", filepath.Join(s.LogDir, "ospd-openvas.log"), "--lock-file-dir", filepath.Dir(s.OSPDSock),
			"--pid-file", filepath.Join(filepath.Dir(s.OSPDSock), "ospd-openvas.pid"))
	})
}

func (s *Supervisor) loop(ctx context.Context, name string, build func() *exec.Cmd) {
	backoff := 2 * time.Second
	for ctx.Err() == nil {
		cmd := build()
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		start := time.Now()
		s.Log.Info("engine process starting", "name", name)
		if err := cmd.Start(); err != nil {
			s.Log.Error("engine process failed to start", "name", name, "err", err)
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, time.Minute)
			continue
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-ctx.Done():
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(30 * time.Second):
				_ = cmd.Process.Kill()
				<-done
			}
			return
		case err := <-done:
			var ee *exec.ExitError
			if errors.As(err, &ee) || err != nil {
				s.Log.Warn("engine process exited", "name", name, "err", err, "after", time.Since(start).Round(time.Second))
			} else {
				s.Log.Warn("engine process exited cleanly; restarting", "name", name)
			}
		}
		if time.Since(start) > 5*time.Minute {
			backoff = 2 * time.Second
		}
		if !sleepCtx(ctx, backoff) {
			return
		}
		backoff = min(backoff*2, time.Minute)
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
