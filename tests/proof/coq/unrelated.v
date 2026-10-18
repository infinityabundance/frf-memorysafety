(* Negative Phase 6.2 seal: a genuine theorem that is outside the manifest's
   declared finite support scope. *)

Require Import Coq.Init.Nat.

Theorem frf_unrelated_arithmetic : forall n : nat, n + 0 = n.
Proof.
  intros n.
  induction n as [| n induction_hypothesis].
  - reflexivity.
  - simpl. rewrite induction_hypothesis. reflexivity.
Qed.
