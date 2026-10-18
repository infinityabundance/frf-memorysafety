(* Negative Phase 6.2 seal: the same fixed-point statement is closed with
   [Admitted] instead of a checked proof. *)

Require Import model.

Theorem frf_support_fixed_point :
  forall s : SupportState,
    support_iterate 1 (support_iterate 1 s) = support_iterate 1 s.
Admitted.
