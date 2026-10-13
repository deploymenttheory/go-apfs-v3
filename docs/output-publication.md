# Completed-output publication

Packing, repacking, recovery and offline image editing share the completed-output
publisher. Original images are opened read-only. A sibling temporary file receives
the output, is flushed and closed, then is linked at a previously absent output
path. An existing file, directory or symlink is never overwritten, including a
destination created during publication. Temporary cleanup precedes the final
directory flush on Unix.

Errors before publication leave the destination absent. Errors after publication
must retain the completed destination: `filesystem.PublishedOutputError` reports
its path and whether the host's supported flushes completed. Its error text says
that the output has already been published. It unwraps the original OS error.
Offline editing also preserves that outcome if later scratch/input cleanup fails.
Cancellation before publication prevents the new name; cancellation after the
name becomes visible finishes the flush and cleanup.

Go `File.Sync` supplies the host file flush. Unix additionally flushes the output
directory. Windows supplies the completed-file flush and atomic name visibility;
this implementation has no unprivileged Windows directory-entry flush guarantee.
Successful flush calls depend on the filesystem and storage honoring their
contracts. These controls do not establish physical hardware power-loss survival.
Live filesystem commits and journal writing belong to writable-mount work.

Fault controls exercise ENOSPC during writing/flushing/linking, directory-flush
failure, cleanup failure, cancellation, publication races and abrupt process
death immediately before/after name publication. A stopped process may leave
private temporary storage; an output name is either absent or refers to completed
bytes. Filesystem acceptance independently checks the published filesystem's
contents and structures, rather than using these fault controls as a semantic
oracle.
