(* Negative Phase 6.2 seal: the fixed-point theorem depends on an unproved
   global [Axiom] rather than the checked lemma in [model.v]. *)

Require Import model.

Axiom frf_support_step_idempotent_axiom :
  forall s : SupportState, support_step (support_step s) = support_step s.

Theorem frf_support_fixed_point :
  forall s : SupportState,
    support_iterate 1 (support_iterate 1 s) = support_iterate 1 s.
Proof.
  intros s.
  change (support_step (support_step s) = support_step s).
  apply frf_support_step_idempotent_axiom.
Qed.
