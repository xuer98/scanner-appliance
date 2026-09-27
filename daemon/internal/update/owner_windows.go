//go:build windows

package update

func dirOwner(string) (uid, gid int, ok bool) { return 0, 0, false }
