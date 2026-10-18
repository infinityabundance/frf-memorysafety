(* A finite two-claim support lattice used by the Phase 6.2 live seal.
   A state records whether the first claim is already reachable and whether
   the second claim has been derived by the rule set.  [support_step] is the
   least-fixed-point iteration operator for this finite domain. *)

Require Import Coq.Init.Nat.
Require Import Coq.Bool.Bool.

Record SupportState := {
  reachable : bool;
  derived : bool
}.

Definition support_step (s : SupportState) : SupportState :=
  {| reachable := orb s.(reachable) s.(derived);
     derived := s.(derived) |}.

Fixpoint support_iterate (n : nat) (s : SupportState) : SupportState :=
  match n with
  | O => s
  | S k => support_step (support_iterate k s)
  end.

Lemma support_step_idempotent :
  forall s : SupportState, support_step (support_step s) = support_step s.
Proof.
  intros [r d].
  simpl.
  destruct d; destruct r; reflexivity.
Qed.
