# Home control: "done" meant accepted, not changed

2026-10-04

Found on the first live run of `control-home-assistant`, the day it shipped.

## The defect

The adapter reported a command `done` on any 2xx. Home Assistant answers a
service call with 200 whether or not anything happened. Measured live, four
commands against a test toggle helper that controls nothing:

| Command | Status | Answer |
|---|---|---|
| turn on (it was off) | 200 | a list of one state |
| turn on again (already on) | 200 | `[]` |
| turn on an entity that does not exist | 200 | `[]` |
| turn off | 200 | a list of one state |

All four were reported `done`. A mistyped entity id in `TARGETS` was
indistinguishable from a command that worked.

## The fix

A `done` result now carries `changed`: the number of states in the service's
answer, counted with `IgnoredAny` so no state is built or kept. The verdict
gains `unchanged`, the done commands that changed nothing. An answer that is
not a list leaves `changed` absent rather than guessing zero. The contract
document says what `done` means, and that an adapter whose system does not
report changes omits the field.

`changed: 0` still has two readings — an entity that does not exist, and a
thing already in the state asked for. The adapter cannot tell them apart
from this answer, and says so rather than picking one.

## Measured

`make check-catalog-fuel`, eight commands, with the recorded answer changed
from `[]` to one realistic state per call (506 bytes): 362,193 fuel of
1,638,000 (22.1%; was 21.0% with an empty answer).

## Test

`accepted_and_changed_are_told_apart`: one state back is `changed: 1`, an
empty list is `changed: 0` and counted `unchanged`, a non-list answer has no
count, the state itself never reaches the output, and a refused or dry-run
command has no count.

## Not verified

The fixed adapter has not run against the live server yet: the installed
copy is the earlier build until it is reinstalled after deploy. The table
above was measured with the earlier build and `capture_http`.
