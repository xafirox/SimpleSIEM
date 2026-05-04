package sieg

// runBackupRemote dispatches the server-mode invocation forms:
//
//	simplesiem backup --agent <id>      [--out-dir <dir>]
//	simplesiem backup --realm <name>    [--out-dir <dir>]
//	simplesiem backup --all             [--out-dir <dir>]
//
// Implementation in backup_remote_pull.go. Split into a separate
// dispatcher file so the CLI parser in backup_cli.go stays small.
func runBackupRemote(args []string) {
	runBackupRemoteServer(args)
}
