package pathid

// FailNextNameForTest swaps the FindNextFileNameW call the enumerator goes
// through for one that fails with err every time it is asked, and returns
// the function that puts the real call back. It exists for tests outside
// this package that interrupt an enumeration partway -- after
// FindFirstFileNameW has already named the file it was asked about -- to
// hold the real callers to what they owe an answer that is not the whole
// list.
func FailNextNameForTest(err error) (restore func()) {
	previous := findNextFileName
	findNextFileName = func(uintptr, *uint32, []uint16) (uintptr, error) { return 0, err }
	return func() { findNextFileName = previous }
}
