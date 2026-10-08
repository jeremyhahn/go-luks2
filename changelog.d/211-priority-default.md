### Changed — BREAKING: `Priority` zero value is `PriorityDefault`

- **`PriorityIgnore` can now be requested, and the zero `Priority` means
  "default" (#211).** `PriorityDefault` is the new zero value of `Priority`.
  It makes a new keyslot normal and leaves a changed keyslot's priority as it
  was. `PriorityIgnore`, `PriorityNormal` and `PriorityPrefer` are now 1/2/3,
  the LUKS2 on-disk value plus one, and each is written when it is asked for.
  Before this change an unset priority and an explicit ignore were the same
  value, so there was no way to create an ignored keyslot. Code that converts
  a `Priority` to or from the LUKS2 integer must add or subtract one. An
  undeclared `Priority` is refused with `ErrInvalidArgument`.
