package scp

import (
	"errors"

	"github.com/google/shlex"
	"github.com/pborman/getopt"
)

// server side scp supports the following flags:
//    -f   "from" or *source* mode
//    -t   "to" or *target* mode
//    -d   target should be a directory
//    -v   "verbose" mode
//    -p   "preserve" modification times  (local side)
//    -r   "recursive" mode

// When copying multiple files to a destination, the destination should be a directory.
// When the client is attempting to copy more than one file, it will pass the `-d` flag
// to ensure the target on the server side is a directory.  (There may be other flows.)
//
// When the preserve timestamps flag is set at the client, it will be added to
// the command sent to the server.  The client will also send the timestamp records.
//
// When the recurive flag is set on the client, it is propagated to the server.  D-E pairs
// are nested to create the file tree structure.
//
// The recursive flag must be set if the source is a directory.
//
// The verbose flag is always propagated.

type Options struct {
	SourceMode           bool
	TargetMode           bool
	TargetIsDirectory    bool
	Verbose              bool
	PreserveTimesAndMode bool
	Recursive            bool
	Quiet                bool

	Sources []string
	Target  string
}

func ParseCommand(command string) ([]string, error) {
	args, err := shlex.Split(command)
	if err != nil {
		return []string{}, err
	}
	return args, err
}

func ParseFlags(args []string) (*Options, error) {
	cmd := args[0]

	// don't allow commands that are not diego-scp
	if cmd != "scp" {
		return nil, errors.New("Usage: call scp")
	}

	// New opts set
	opts := getopt.New()

	// target mode option is optional
	targetMode := opts.Bool('t', "", "Sets target mode for scp")
	opts.Lookup('t').SetOptional()

	// source mode option is optional
	sourceMode := opts.Bool('f', "", "Sets source mode for scp")
	opts.Lookup('f').SetOptional()

	// target is a directory option is optional
	targetIsDirectory := opts.Bool('d', "", "Indicates that the target is a directory")
	opts.Lookup('d').SetOptional()

	// verbose option is optional
	verbose := opts.Bool('v', "", "Indicates that the command should be run in verbose mode")
	opts.Lookup('v').SetOptional()

	// preserve times option is optional
	preserveTimesAndMode := opts.Bool('p', "", "Indicates that scp should preserve timestamps and mode of files/directories transferred")
	opts.Lookup('p').SetOptional()

	// recursive option is optional
	recursive := opts.Bool('r', "", "Indicates a recursive transfer, must be set if source is a directory")
	opts.Lookup('r').SetOptional()

	// showprogress option is not used but can be provided
	quiet := opts.Bool('q', "", "Indicates that the user wishes to run in quiet mode")
	opts.Lookup('q').SetOptional()

	// parse flags
	err := opts.Getopt(args, nil)
	if err != nil {
		return nil, err
	}

	// don't allow target/source mode both to be set or not
	if *targetMode == *sourceMode {
		return nil, errors.New("Must specify either target mode(-t) or source mode(-f) at a time")
	}

	var sources []string
	var target string

	// populate sources if in source mode
	if *sourceMode {
		if len(opts.Args()) < 1 {
			return nil, errors.New("Must specify at least one source in source mode")
		}

		sources = opts.Args()
	}

	// populate target if in target mode
	if *targetMode {
		if len(opts.Args()) != 1 {
			return nil, errors.New("Must specify one target in target mode")
		}

		target = opts.Args()[0]
	}

	return &Options{
		TargetMode:           *targetMode,
		SourceMode:           *sourceMode,
		TargetIsDirectory:    *targetIsDirectory,
		Verbose:              *verbose,
		PreserveTimesAndMode: *preserveTimesAndMode,
		Recursive:            *recursive,
		Quiet:                *quiet,
		Sources:              sources,
		Target:               target,
	}, nil
}
