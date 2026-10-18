# Phase 3.2: explicit path effects and qualified outcomes

Snapshot: branch `staging`, crate `frf-memorysafety 0.3.0`. This document
describes the Phase 3.2 finite path-effect model only. Phase 3.3 adds optional
MIR text observations, but source/MIR-extracted alias, provenance, footprint,
reference-interval semantics, and native observation remain unimplemented.

## Claim ceiling

The model consumes an **explicit finite trace**: caller-supplied objects,
aliases, reference intervals, events, callbacks, and providers. It does not
parse a caller graph, resolve types or MIR, extract aliases from source, execute
native code, observe a real C callback, or prove a whole-program property.

A completed analysis establishes only that the declared finite model was
internally qualified under the rules below. It does not establish:

* that a source-level alias, footprint, or reference interval was discovered;
* that a callback was registered, invoked, or legal under a C contract;
* anything about threads, data races, synchronization, or concurrent access;
* C effective-type, alignment, or object-representation legality;
* any native memory-safety property or universal Rust soundness.

Absence of an observed conflict is never evidence of absence. A
`compatible_within_finite_footprint` result is limited to the declared finite
footprint. Foreign and provider behavior is preserved as unknown; it is never
promoted to safe or unsafe.

## Typed model

### Aliases

| Alias kind | Relationship used by the model |
|---|---|
| `exact_object` | Denotes the declared object exactly. Two different object ids are disjoint. |
| `descendant` | Derived pointer or subrange of the declared object. An explicit `range` gives a byte interval; without one the descendant extent is unknown. |
| `shared_mapping` | A view through a shared mapping. The same `mapping` id is the same storage for explicit range comparison. Different mapping ids, and a mapping versus an object, remain **possible** aliases, never proven disjoint. |
| `top_unknown` | No object identity. Overlap with any access is possible. |

`interior_mutable` is an object flag used only to suppress a read/write pair on
the same object. It does not suppress write/write conflicts, use-after-free,
double-free, or reference-interval violations.

### Footprints

| Footprint | Extent used by the model |
|---|---|
| `exact` | Whole declared object. |
| `descendant` | Explicit event `range`, else the alias `range`, else unknown. |
| `top` | Unknown extent. |

### Reference intervals

A reference interval is an explicit half-open program-point window
`[start, end)`. An omitted `end` is open to the end of the trace. An event with
no interval is a point window `[point, point + 1)`. Two accesses are considered
simultaneously live only when their windows overlap. An event whose point lies
outside its declared interval is an `observed_conflict`.

### Events

Events are ordered by the explicit unique `point`: `creation`, `reborrow`,
`escape`, `callback`, `free`, and `use`. Every event names an alias, an access
mode (`read`, `write`, or `none`), and a footprint.

### Callbacks and providers

| Declaration | Qualification |
|---|---|
| Observed `synchronous_legal` callback | No extra uncertainty; normal event rules apply. |
| Observed `retained_pointer` callback | `not_falsified`: a pointer may escape and be used later. |
| Observed `deferred` callback | `not_falsified`: invocation may occur after the registering call. |
| `callback_after_free` | `not_falsified` as a declaration; an explicit callback event after a free is an `observed_conflict`. |
| `foreign_provider_dispatch` callback | `not_falsified`: dispatch remains foreign/unknown. |
| Declared callback not observed, `legally_absent: true` | `omission`: the model states that absence is legal in this finite trace. |
| Declared callback not observed, `legally_absent: false` | `not_falsified`: it could still occur outside the trace. |
| Any `foreign_unknown` or `dynamic_dispatch` provider | `not_falsified`; never implicitly safe or unsafe. |

## Event and footprint algebra

Storage relation:

```text
same_object(x, y)      = same object id
same_mapping(m, m)     = same storage for explicit range comparison
different_object(x,y)  = disjoint
mapping vs mapping     = same if mapping id matches, otherwise possible
mapping vs object      = possible
top vs anything        = possible
```

Extent relation and overlap:

```text
extent(event) = exact | range(offset, length) | unknown

overlap(storage, extent_a, extent_b):
  storage disjoint                    -> disjoint
  storage possible                    -> possible
  exact / exact                       -> definite
  exact / range                       -> definite
  range(a) / range(b)                 -> definite if ranges intersect, else disjoint
  any pair with unknown               -> possible
```

A pairwise memory conflict requires all of the following:

1. at least one access is a write (read/read pairs are not conflicts);
2. the reference windows overlap;
3. the storage relation is not disjoint;
4. the overlap relation is not disjoint;
5. the common object is not `interior_mutable` in a read/write pair.

`definite` overlap yields `observed_conflict`; `possible` overlap yields
`not_falsified` together with the explicit unknown codes that caused it.

Lifecycle rules are separate:

* two frees of the same explicit object are a definite `double_free`;
* two frees that may share storage are a `possible_double_free`;
* any later event on the same object is a definite use-after-free
  (`callback_after_free` for a callback event);
* a later event on possibly-same storage is a possible use-after-free.

## Qualified outcomes

The model does not collapse outcomes into a boolean.

| Status | Meaning |
|---|---|
| `observed_conflict` | A definite conflict or lifecycle/interval violation was observed in the declared trace. |
| `omission` | The event was not observed and the model states that its absence is legal in this finite trace. |
| `not_falsified` | The event or overlap could still occur through an explicit unknown alias, footprint, callback, or provider. |
| `compatible_within_finite_footprint` | Every observed access is disjoint or legally ordered within the declared finite footprint, with no unresolved uncertainty recorded. |

`not_falsified` is not a weak `compatible`, and `compatible` is not
whole-program or universal closure. The report's `overall` field is only a
report label chosen by the priority `observed_conflict` > `not_falsified` >
`omission` > `compatible`; the per-outcome records retain every distinction.

## §12.4 omission versus not-falsified

The latest paper's §12.4 distinguishes three coverage outcomes:

1. an observed legal callback missing from the declared inventory falsifies the
   inventory;
2. a declared callback not observed in finite runs is `NOT_FALSIFIED`, not
   conservative closure;
3. an observed declared callback is also `NOT_FALSIFIED`, not proof that no
   other edge exists.

Phase 3.2 preserves this distinction at event level. Two traces can both lack
an observed conflict and still differ:

* an unobserved callback with `legally_absent: true` yields `omission`;
* an unobserved callback with `legally_absent: false` yields `not_falsified`
  with the `callback_not_observed` unknown.

Neither result establishes conservative closure.

## Input and CLI

```text
frf-memorysafety path analyze FILE [--json]
```

`FILE` is either:

* `frf-memorysafety.path-effects-input.v1`, an explicit finite trace; or
* `frf-memorysafety.source-inventory.v1`, the Phase 3.1 inventory.

The CLI is hand-written and never executes a shell. Both spellings emit the
same strict canonical `ms-canonical-json-v1` bytes with no trailing newline.
The report schema is `frf-memorysafety.path-effects-report.v1`.

Example explicit input:

```json
{
  "schema": "frf-memorysafety.path-effects-input.v1",
  "spec": "frf-memorysafety-spec-v1",
  "objects": [{ "id": "a", "interior_mutable": false }],
  "aliases": [{ "id": "p", "kind": "exact_object", "object": "a" }],
  "intervals": [{ "id": "i1", "alias": "p", "start": 0, "end": 4 }],
  "events": [{
    "point": 0,
    "kind": "use",
    "alias": "p",
    "access": "write",
    "footprint": { "kind": "exact" },
    "interval": "i1"
  }],
  "callbacks": [],
  "providers": []
}
```

An inventory has no alias, object, interval, or dispatch identity. The adapter
therefore emits one `top_unknown` alias, a top footprint for every derived
event, and an explicit foreign-dispatch provider. Allocation, deallocation,
callback-registration, `UnsafeCell`, raw-pointer, ownership, and FFI-call
findings become coarse events. An inventory-derived report is expected to be
`not_falsified`; it is never compatibility evidence.

Exit statuses follow `SPEC.md` §14:

| Status | Meaning for `path analyze` |
|---:|---|
| `0` | analysis completed; qualified outcomes are in the report (including observed conflicts) |
| `2` | missing file, bad flag, or usage error |
| `3` | invalid input, unknown schema, structural violation, or limit violation |
| `7` | internal canonical-encoding failure |

An observed conflict is a finding, not a command failure, so it exits `0` while
the report records `observed_conflict`.

## Limits and determinism

| Resource | Default |
|---|---:|
| events | 1,024 |
| pairwise event checks | 1,048,576 |
| qualified outcome records | 65,536 |
| canonical report bytes | 4 MiB (`ms-canonical-json-v1`) |

Exceeding a limit is an integrity error, never truncation. Events are sorted by
program point; outcomes and unknowns are `BTreeSet`s; summaries are
`BTreeMap`s. Equal inputs therefore produce equal canonical report bytes. The
report embeds the SHA-256 of the canonical consumed input.

## Seal controls

`tests/path_effects.rs` executes every control; no test is ignored.

| Control | Expected qualification |
|---|---|
| Exact versus descendant confusion | Exact whole-object overlap is `observed_conflict`; disjoint descendant ranges are `compatible`. |
| Descendant versus top confusion | Disjoint explicit descendant ranges are `compatible`; a top alias makes the same pair `not_falsified`, never a definite conflict. |
| Wrong shared mapping | A shared mapping is not treated as an independent allocation: disjoint-looking ranges become `not_falsified`; explicit same-mapping overlap is still `observed_conflict`. |
| Omitted alias | Removing a top/unknown alias changes `not_falsified` to `compatible`; omission is not silently treated as evidence. |
| Benign `UnsafeCell` | Read/write interior mutation on the same `interior_mutable` object is `compatible`; write/write remains `observed_conflict`. |
| Independent allocations | Two different object ids with writes are `compatible`. |
| Legal synchronous callback | `compatible_within_finite_footprint`. |
| Retained pointer | `not_falsified` (`retained_pointer_escaped`). |
| Deferred callback | `not_falsified` (`deferred_callback`). |
| Callback after free | `observed_conflict` (`callback_after_free`). |
| Foreign/provider dispatch | `not_falsified`; never promoted to safe or unsafe. |
| §12.4 pair | Unobserved `legally_absent` callback is `omission`; unobserved non-absent callback is `not_falsified`. |
| Reference intervals | An out-of-window event is `observed_conflict`; disjoint windows are `compatible`. |
| Inventory adapter | Always `not_falsified` through a top alias and foreign provider. |

## Honest remaining unknowns (Phase 3.3)

* No source-to-model mapping is justified: a real Rust alias, provenance, or
  reference interval is not extracted.
* No compiler-resolved alias, type, or ownership identity is used. The Phase
  3.3 MIR adapter observes unresolved textual edges only.
* Shared-mapping physical identity is a declared premise, not measured.
* No native callback registration, invocation, retention, or after-free event is
  observed.
* No concurrency, synchronization, data-race, or reentrancy model is present.
* C effective-type, alignment, and object-representation legality are outside
  the byte-range model.
* No whole-program closure, detector calibration, or universal soundness is
  established.

## Citations

1. The Rust Reference, **Behavior considered undefined** — aliasing rules,
   live-reference bounds, the `UnsafeCell` exception, dangling pointers, and
   invalid values. The model's read/write and interval distinctions follow this
   outline but do not claim to implement the unspecified exact aliasing rules.
   <https://doc.rust-lang.org/reference/behavior-considered-undefined.html>
2. Rust Unsafe Code Guidelines Reference, **Glossary** — aliasing as overlap of
   byte spans, allocation identity, pointer provenance, and interior
   mutability. Basis for the object/descendant/top distinctions.
   <https://rust-lang.github.io/unsafe-code-guidelines/glossary.html>
3. R. Jung, H.-H. Dang, J. Kang, D. Dreyer, **Stacked Borrows: An Aliasing
   Model for Rust**, POPL 2020. A proposed operational aliasing discipline; it
   is not implemented here. <https://plv.mpi-sws.org/rustbelt/stacked-borrows/>
4. The Rustonomicon, **Foreign Function Interface** — C callbacks, callback
   targets, asynchronous callbacks, pointer validity across FFI, and the
   requirement that no callback occurs after the target is destroyed. Basis for
   the callback qualification cases.
   <https://doc.rust-lang.org/nomicon/ffi.html>
5. ISO/IEC 9899:2018 (C17), §6.5 paragraphs 6–7 (effective type and strict
   aliasing), and ISO/IEC 9899:2011 (C11) N1570. C object identity, effective
   type, and aliasing are properties of the foreign contract; this model only
   records explicit byte ranges. <https://www.open-std.org/jtc1/sc22/wg14/www/docs/n1570.pdf>
6. N. Vanille, **Tree Borrows** — a later experimental Rust aliasing model and
   alternative to Stacked Borrows. It is cited as disagreement in the research
   literature, not implemented here.
   <https://github.com/Vanille-N/tree-borrows>
7. The Rust Reference, **Pointer types** — raw pointers carry no safety or
   liveness guarantees, and dereferencing is unsafe. Basis for treating raw
   alias identity as a declared input rather than a source-derived fact.
   <https://doc.rust-lang.org/reference/types/pointer.html>
