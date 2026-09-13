package usage

// Detail returns the full help for one command, and whether that command
// exists. Aliases are resolved by the caller.
func Detail(name string) (string, bool) {
	for _, command := range Commands {
		if command.Name == name {
			return command.String(), true
		}
	}
	return "", false
}
