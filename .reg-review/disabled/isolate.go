package acl

func Isolate(path, account string, entries []ACE, reach uint32) error {
	return Set(path, account, entries)
}
