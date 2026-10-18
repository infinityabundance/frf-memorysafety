(* Positive Phase 6.2 seal: the finite support iteration reaches a fixed
   point after one step.  This is a genuine theorem about the two-claim
   least-fixed-point model in [model.v]. *)

Require Import model.

Theorem frf_support_fixed_point :
  forall s : SupportState,
    support_iterate 1 (support_iterate 1 s) = support_iterate 1 s.
Proof.
  intros s.
  change (support_step (support_step s) = support_step s).
  apply support_step_idempotent.
Qed.
