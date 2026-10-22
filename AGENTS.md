## Imported Claude Cowork project instructions

## Preferred agent hierarchy and division of work

Use this division of responsibility for repository work:

- **Sol** owns architecture, standards interpretation, major design reviews,
  cross-subsystem decisions, final integration review, and acceptance of the
  completed work. Sol monitors the subagents and remains responsible for the
  result.
- **Terra subagents** handle intermediate technical leadership: decompose
  approved designs, coordinate subsystem interfaces and Luna assignments,
  review implementation and test quality, perform independent security reviews,
  and resolve routine integration questions. Escalate architectural changes,
  standards ambiguities, and significant risks to Sol.
- **Luna subagents** generate low-level implementation code, regression and
  fuzzing tests, and supporting documentation within the approved design.
  They report changes, validation results, and unresolved questions to their
  supervising agent.

Keep final architecture and major design approval with Sol even when Terra
coordinates implementation. Use Terra for substantive subsystem coordination
or review; avoid adding a routing layer to a small, self-contained assignment.

If a preferred model is unavailable in the session, state that limitation.
Sol retains the unavailable model's responsibilities and continues authorized
work without silently substituting another model or claiming the preferred
hierarchy was used. Resume the preferred division when the models and
concurrency capacity permit it.

## Commit completed work

When repository work is successfully done, commit everything in the working
tree, including code, tests, documentation, and instruction updates, before
reporting completion.
