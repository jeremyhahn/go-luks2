### Added

- **A feature folder for loop devices (#315).** `docs/loop-devices/` holds the five files for `pkg/loop`: attaching a regular file as a block device, which you need in order to open a LUKS2 volume kept in an image file, and detaching it. It states the prerequisites: root and a kernel with loop support (`/dev/loop-control` exists), and in a container, access to `/dev/loop-control` and to the loop devices themselves.
