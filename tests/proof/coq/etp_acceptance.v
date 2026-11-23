(* Phase 16.1a: finite abstract acceptance core for ETP-FORMAL-ACCEPTANCE.

   This file mechanises the small, finite acceptance predicate used by the
   Earned Trust Protocol campaign model. It does not prove the Rust
   implementation, native execution, or universal soundness. Its only claim is
   the one recorded in the manifest scope: within a finite universe of four
   premises, three claims and four derivation rules, admission requires a
   present, unchallenged, unrevoked finite derivation, and every declared policy
   invariant blocks the corresponding mutated state.

   Design notes:
   - `derivation` is an inductive indexed by the claim it establishes. Every
     inhabitant is a finite constructor tree, so a cyclic derivation is not a
     well-typed term. The claim index also prevents a proof of one claim from
     being used as a proof of another claim.
   - `admitted_via` is the single acceptance rule. `admitted` is its
     existential closure. Every theorem below either extracts an obligation
     from that rule or shows that a mutated policy/state cannot satisfy it.
   - No axioms, parameters, admitted lemmas or opaque assumptions are used. *)

Require Import Coq.Init.Nat.
Require Import Coq.Lists.List.
Require Import Lia.

Import ListNotations.

(* ------------------------------------------------------------------ *)
(* 1. Finite premise and claim universe                                *)
(* ------------------------------------------------------------------ *)

Inductive premise_id : Type := pA | pB | pC | pD.

Inductive claim_id : Type := c0 | c1 | c2.

(* A derivation is a finite proof tree. The inductive declaration makes every
   derivation finite by construction: a cyclic derivation cannot be built. *)
Inductive derivation : claim_id -> Type :=
| derive_c0_from_a : derivation c0
| derive_c1_from_b : derivation c1
| derive_c0_from_c : derivation c0
| derive_c2_from_c0_c1 : derivation c0 -> derivation c1 -> derivation c2.

Fixpoint premises {c : claim_id} (d : derivation c) : list premise_id :=
  match d with
  | derive_c0_from_a => [pA]
  | derive_c1_from_b => [pB]
  | derive_c0_from_c => [pC]
  | derive_c2_from_c0_c1 d0 d1 => premises d0 ++ premises d1
  end.

Fixpoint derivation_size {c : claim_id} (d : derivation c) : nat :=
  match d with
  | derive_c0_from_a => 1
  | derive_c1_from_b => 1
  | derive_c0_from_c => 1
  | derive_c2_from_c0_c1 d0 d1 => S (derivation_size d0 + derivation_size d1)
  end.

(* ------------------------------------------------------------------ *)
(* 2. Declared policy and observed state                               *)
(* ------------------------------------------------------------------ *)

Record policy := {
  policy_version : nat;
  candidate_id : nat;
  campaign_required : bool;
  required_actors : nat;
  freshness_required : bool;
  archive_required : bool;
  required_premises : list premise_id
}.

Record state := {
  observed_policy_version : nat;
  bound_candidate : nat;
  reported_claim : claim_id;
  present : premise_id -> bool;
  challenged : premise_id -> bool;
  revoked : premise_id -> bool;
  campaign_closed : bool;
  independent_actors : nat;
  transparency_fresh : bool;
  archive_present : bool;
  authenticated : bool
}.

(* ------------------------------------------------------------------ *)
(* 3. Acceptance rule                                                  *)
(* ------------------------------------------------------------------ *)

Definition premise_ok (s : state) (q : premise_id) : Prop :=
  s.(present) q = true /\
  s.(challenged) q = false /\
  s.(revoked) q = false.

Definition all_premises_ok (s : state) (qs : list premise_id) : Prop :=
  Forall (premise_ok s) qs.

Definition required_present (p : policy) (s : state) : Prop :=
  Forall (fun q => s.(present) q = true) p.(required_premises).

Definition policy_satisfied (p : policy) (s : state) : Prop :=
  p.(policy_version) = s.(observed_policy_version) /\
  p.(candidate_id) = s.(bound_candidate) /\
  (p.(campaign_required) = true -> s.(campaign_closed) = true) /\
  (p.(required_actors) <= s.(independent_actors)) /\
  (p.(freshness_required) = true -> s.(transparency_fresh) = true) /\
  (p.(archive_required) = true -> s.(archive_present) = true) /\
  required_present p s.

(* One derivation supports one claim under one policy and one observed state.
   Authentication is deliberately absent from this rule: a valid signature is
   not semantic support. *)
Definition admitted_via
    (p : policy) (s : state) (c : claim_id) (d : derivation c) : Prop :=
  policy_satisfied p s /\
  s.(reported_claim) = c /\
  all_premises_ok s (premises d).

Definition admitted (p : policy) (s : state) (c : claim_id) : Prop :=
  exists d : derivation c, admitted_via p s c d.

(* ------------------------------------------------------------------ *)
(* 4. Projection lemmas                                                *)
(* ------------------------------------------------------------------ *)

Lemma satisfied_version :
  forall (p : policy) (s : state),
    policy_satisfied p s -> p.(policy_version) = s.(observed_policy_version).
Proof. intros p s [H _]. exact H. Qed.

Lemma satisfied_candidate :
  forall (p : policy) (s : state),
    policy_satisfied p s -> p.(candidate_id) = s.(bound_candidate).
Proof. intros p s [_ [H _]]. exact H. Qed.

Lemma satisfied_campaign :
  forall (p : policy) (s : state),
    policy_satisfied p s ->
    p.(campaign_required) = true -> s.(campaign_closed) = true.
Proof. intros p s [_ [_ [H _]]]. exact H. Qed.

Lemma satisfied_actors :
  forall (p : policy) (s : state),
    policy_satisfied p s -> p.(required_actors) <= s.(independent_actors).
Proof. intros p s [_ [_ [_ [H _]]]]. exact H. Qed.

Lemma satisfied_freshness :
  forall (p : policy) (s : state),
    policy_satisfied p s ->
    p.(freshness_required) = true -> s.(transparency_fresh) = true.
Proof. intros p s [_ [_ [_ [_ [H _]]]]]. exact H. Qed.

Lemma satisfied_archive :
  forall (p : policy) (s : state),
    policy_satisfied p s ->
    p.(archive_required) = true -> s.(archive_present) = true.
Proof. intros p s [_ [_ [_ [_ [_ [H _]]]]]]. exact H. Qed.

Lemma satisfied_required :
  forall (p : policy) (s : state),
    policy_satisfied p s -> required_present p s.
Proof. intros p s [_ [_ [_ [_ [_ [_ H]]]]]]. exact H. Qed.

Lemma admitted_via_satisfied :
  forall (p : policy) (s : state) (c : claim_id) (d : derivation c),
    admitted_via p s c d -> policy_satisfied p s.
Proof. intros p s c d [H _]. exact H. Qed.

Lemma admitted_via_claim :
  forall (p : policy) (s : state) (c : claim_id) (d : derivation c),
    admitted_via p s c d -> s.(reported_claim) = c.
Proof. intros p s c d [_ [H _]]. exact H. Qed.

Lemma admitted_via_premises :
  forall (p : policy) (s : state) (c : claim_id) (d : derivation c),
    admitted_via p s c d -> all_premises_ok s (premises d).
Proof. intros p s c d [_ [_ H]]. exact H. Qed.

Lemma forall_in_premise_ok :
  forall (s : state) (qs : list premise_id) (q : premise_id),
    all_premises_ok s qs -> In q qs -> premise_ok s q.
Proof.
  intros s qs. induction qs as [| x xs IH]; intros q Hf Hin.
  - inversion Hin.
  - simpl in Hin. simpl in Hf.
    destruct Hin as [Heq | Hin].
    + subst. apply (Forall_inv Hf).
    + apply IH.
      * apply (Forall_inv_tail Hf).
      * exact Hin.
Qed.

Lemma premise_ok_present :
  forall (s : state) (q : premise_id), premise_ok s q -> s.(present) q = true.
Proof. intros s q [H _]. exact H. Qed.

Lemma premise_ok_not_challenged :
  forall (s : state) (q : premise_id), premise_ok s q -> s.(challenged) q = false.
Proof. intros s q [_ [H _]]. exact H. Qed.

Lemma premise_ok_not_revoked :
  forall (s : state) (q : premise_id), premise_ok s q -> s.(revoked) q = false.
Proof. intros s q [_ [_ H]]. exact H. Qed.

Lemma required_present_in :
  forall (p : policy) (s : state) (q : premise_id),
    required_present p s ->
    In q p.(required_premises) ->
    s.(present) q = true.
Proof.
  intros [pv cid camp actors fresh arch req] s q Hf Hin.
  unfold required_present in Hf. simpl in Hf, Hin.
  induction req as [| x xs IH].
  - inversion Hin.
  - simpl in Hf. simpl in Hin.
    destruct Hin as [Heq | Hin].
    + subst. exact (Forall_inv Hf).
    + apply IH.
      * exact (Forall_inv_tail Hf).
      * exact Hin.
Qed.

(* ------------------------------------------------------------------ *)
(* 5. Priority invariants                                              *)
(* ------------------------------------------------------------------ *)

(* Invariant 1: no unsupported or cyclic admission. Admission yields a finite
   derivation (by type) whose premises are present, unchallenged and unrevoked. *)
Theorem no_unsupported_or_cyclic_admission :
  forall (p : policy) (s : state) (c : claim_id),
    admitted p s c -> exists d : derivation c, all_premises_ok s (premises d).
Proof.
  intros p s c [d Hvia].
  exists d. exact (admitted_via_premises p s c d Hvia).
Qed.

(* Invariant 2: missing mandatory evidence blocks acceptance. *)
Theorem missing_mandatory_evidence_blocks :
  forall (p : policy) (s : state) (c : claim_id) (q : premise_id),
    In q p.(required_premises) ->
    s.(present) q = false ->
    ~ admitted p s c.
Proof.
  intros p s c q Hin Hmissing [d Hvia].
  pose proof (satisfied_required p s
                (admitted_via_satisfied p s c d Hvia)) as Hreq.
  pose proof (required_present_in p s q Hreq Hin) as Hpresent.
  rewrite Hmissing in Hpresent. discriminate.
Qed.

(* Invariant 3: candidate substitution invalidates acceptance. *)
Theorem candidate_substitution_invalidates :
  forall (p : policy) (s : state) (c : claim_id),
    p.(candidate_id) <> s.(bound_candidate) -> ~ admitted p s c.
Proof.
  intros p s c Hne [d Hvia].
  pose proof (satisfied_candidate p s
                (admitted_via_satisfied p s c d Hvia)) as Hcand.
  apply Hne. exact Hcand.
Qed.

(* Invariant 4: authentication is not semantic support. A valid signature over
   a state with no admissible derivation is still refused. *)
Theorem authentication_is_not_semantic_support :
  forall (p : policy) (s : state) (c : claim_id),
    s.(authenticated) = true ->
    (forall d : derivation c, ~ all_premises_ok s (premises d)) ->
    ~ admitted p s c.
Proof.
  intros p s c Hauth Hnosup [d Hvia].
  exact (Hnosup d (admitted_via_premises p s c d Hvia)).
Qed.

(* Invariant 5: a proof of a different claim does not satisfy the requested
   claim. The reported claim must be the claim under evaluation. *)
Theorem unrelated_proof_does_not_satisfy :
  forall (p : policy) (s : state) (c : claim_id),
    s.(reported_claim) <> c -> ~ admitted p s c.
Proof.
  intros p s c Hne [d Hvia].
  pose proof (admitted_via_claim p s c d Hvia) as Hclaim.
  apply Hne. exact Hclaim.
Qed.

(* Invariant 6: a challenged premise cannot support an admitted derivation.
   When every derivation of the claim requires that premise, admission is
   refused outright. *)
Theorem challenged_premise_blocks :
  forall (p : policy) (s : state) (c : claim_id) (q : premise_id),
    (forall d : derivation c, In q (premises d)) ->
    s.(challenged) q = true ->
    ~ admitted p s c.
Proof.
  intros p s c q Hall Hchall [d Hvia].
  pose proof (admitted_via_premises p s c d Hvia) as Hok.
  pose proof (forall_in_premise_ok s (premises d) q Hok (Hall d)) as Hq.
  pose proof (premise_ok_not_challenged s q Hq) as Hfalse.
  rewrite Hchall in Hfalse. discriminate.
Qed.

(* Invariant 7: a revoked premise invalidates every derivation that requires
   it, and therefore admission when no alternative support exists. *)
Theorem revoked_premise_invalidates :
  forall (p : policy) (s : state) (c : claim_id) (q : premise_id),
    (forall d : derivation c, In q (premises d)) ->
    s.(revoked) q = true ->
    ~ admitted p s c.
Proof.
  intros p s c q Hall Hrevoked [d Hvia].
  pose proof (admitted_via_premises p s c d Hvia) as Hok.
  pose proof (forall_in_premise_ok s (premises d) q Hok (Hall d)) as Hq.
  pose proof (premise_ok_not_revoked s q Hq) as Hfalse.
  rewrite Hrevoked in Hfalse. discriminate.
Qed.

(* Invariant 8: an incomplete campaign cannot satisfy a policy that requires
   campaign completeness. *)
Theorem incomplete_campaign_blocks :
  forall (p : policy) (s : state) (c : claim_id),
    p.(campaign_required) = true ->
    s.(campaign_closed) = false ->
    ~ admitted p s c.
Proof.
  intros p s c Hreq Hclosed [d Hvia].
  pose proof (satisfied_campaign p s
                (admitted_via_satisfied p s c d Hvia) Hreq) as Htrue.
  rewrite Htrue in Hclosed. discriminate.
Qed.

(* Invariant 9: duplicated credentials below the declared threshold do not
   satisfy an independent-actor requirement. *)
Theorem duplicate_credentials_do_not_satisfy_independence :
  forall (p : policy) (s : state) (c : claim_id),
    s.(independent_actors) < p.(required_actors) -> ~ admitted p s c.
Proof.
  intros p s c Hlt [d Hvia].
  pose proof (satisfied_actors p s
                (admitted_via_satisfied p s c d Hvia)) as Hle.
  lia.
Qed.

(* Invariant 10: stale transparency state cannot satisfy a freshness policy. *)
Theorem stale_transparency_blocks :
  forall (p : policy) (s : state) (c : claim_id),
    p.(freshness_required) = true ->
    s.(transparency_fresh) = false ->
    ~ admitted p s c.
Proof.
  intros p s c Hreq Hstale [d Hvia].
  pose proof (satisfied_freshness p s
                (admitted_via_satisfied p s c d Hvia) Hreq) as Htrue.
  rewrite Htrue in Hstale. discriminate.
Qed.

(* Invariant 11: a missing required archive cannot satisfy reconstruction. *)
Theorem missing_archive_blocks_reconstruction :
  forall (p : policy) (s : state) (c : claim_id),
    p.(archive_required) = true ->
    s.(archive_present) = false ->
    ~ admitted p s c.
Proof.
  intros p s c Hreq Hmiss [d Hvia].
  pose proof (satisfied_archive p s
                (admitted_via_satisfied p s c d Hvia) Hreq) as Htrue.
  rewrite Htrue in Hmiss. discriminate.
Qed.

(* Invariant 12: policy substitution cannot preserve an unauthorised
   acceptance decision. *)
Theorem policy_substitution_blocks :
  forall (p : policy) (s : state) (c : claim_id),
    p.(policy_version) <> s.(observed_policy_version) -> ~ admitted p s c.
Proof.
  intros p s c Hne [d Hvia].
  pose proof (satisfied_version p s
                (admitted_via_satisfied p s c d Hvia)) as Hver.
  apply Hne. exact Hver.
Qed.

(* Supporting theorem: every derivation is finite and non-empty. This is what
   rules out a cyclic-only "support" object at the model level. *)
Theorem every_derivation_is_finite :
  forall (c : claim_id) (d : derivation c), 1 <= derivation_size d.
Proof.
  intros c d. destruct d; simpl; lia.
Qed.

(* Supporting theorem: the acceptance rule is inhabited. The negative
   invariants above therefore constrain a non-vacuous predicate. *)
Definition sample_policy : policy :=
  {| policy_version := 1;
     candidate_id := 7;
     campaign_required := true;
     required_actors := 2;
     freshness_required := true;
     archive_required := true;
     required_premises := [pA; pB] |}.

Definition sample_state : state :=
  {| observed_policy_version := 1;
     bound_candidate := 7;
     reported_claim := c2;
     present := fun q =>
       match q with pA => true | pB => true | pC => true | pD => true end;
     challenged := fun _ => false;
     revoked := fun _ => false;
     campaign_closed := true;
     independent_actors := 2;
     transparency_fresh := true;
     archive_present := true;
     authenticated := true |}.

Lemma sample_required_present :
  required_present sample_policy sample_state.
Proof.
  unfold required_present. simpl.
  repeat constructor; reflexivity.
Qed.

Lemma sample_policy_satisfied :
  policy_satisfied sample_policy sample_state.
Proof.
  unfold policy_satisfied, required_present.
  cbn.
  split; [reflexivity|].
  split; [reflexivity|].
  split; [intros _; reflexivity|].
  split; [apply le_n|].
  split; [intros _; reflexivity|].
  split; [intros _; reflexivity|].
  repeat constructor; reflexivity.
Qed.

Theorem acceptance_core_inhabited :
  exists (p : policy) (s : state) (c : claim_id), admitted p s c.
Proof.
  exists sample_policy, sample_state, c2.
  unfold admitted.
  exists (derive_c2_from_c0_c1 derive_c0_from_a derive_c1_from_b).
  unfold admitted_via.
  split; [exact sample_policy_satisfied|].
  split; [reflexivity|].
  unfold all_premises_ok, premise_ok. simpl.
  repeat constructor; reflexivity.
Qed.

(* The campaign theorem. It is the conjunction of every priority invariant and
   is proved by invoking each invariant theorem. The manifest closure is
   therefore the real dependency closure of this theorem, not a padded list. *)
Theorem acceptance_core_sound :
  (forall (p : policy) (s : state) (c : claim_id),
      admitted p s c ->
      exists d : derivation c, all_premises_ok s (premises d)) /\
  (forall (p : policy) (s : state) (c : claim_id) (q : premise_id),
      In q p.(required_premises) ->
      s.(present) q = false ->
      ~ admitted p s c) /\
  (forall (p : policy) (s : state) (c : claim_id),
      p.(candidate_id) <> s.(bound_candidate) -> ~ admitted p s c) /\
  (forall (p : policy) (s : state) (c : claim_id),
      s.(authenticated) = true ->
      (forall d : derivation c, ~ all_premises_ok s (premises d)) ->
      ~ admitted p s c) /\
  (forall (p : policy) (s : state) (c : claim_id),
      s.(reported_claim) <> c -> ~ admitted p s c) /\
  (forall (p : policy) (s : state) (c : claim_id) (q : premise_id),
      (forall d : derivation c, In q (premises d)) ->
      s.(challenged) q = true ->
      ~ admitted p s c) /\
  (forall (p : policy) (s : state) (c : claim_id) (q : premise_id),
      (forall d : derivation c, In q (premises d)) ->
      s.(revoked) q = true ->
      ~ admitted p s c) /\
  (forall (p : policy) (s : state) (c : claim_id),
      p.(campaign_required) = true ->
      s.(campaign_closed) = false ->
      ~ admitted p s c) /\
  (forall (p : policy) (s : state) (c : claim_id),
      s.(independent_actors) < p.(required_actors) -> ~ admitted p s c) /\
  (forall (p : policy) (s : state) (c : claim_id),
      p.(freshness_required) = true ->
      s.(transparency_fresh) = false ->
      ~ admitted p s c) /\
  (forall (p : policy) (s : state) (c : claim_id),
      p.(archive_required) = true ->
      s.(archive_present) = false ->
      ~ admitted p s c) /\
  (forall (p : policy) (s : state) (c : claim_id),
      p.(policy_version) <> s.(observed_policy_version) -> ~ admitted p s c) /\
  (forall (c : claim_id) (d : derivation c), 1 <= derivation_size d) /\
  (exists (p : policy) (s : state) (c : claim_id), admitted p s c).
Proof.
  repeat split.
  - exact no_unsupported_or_cyclic_admission.
  - exact missing_mandatory_evidence_blocks.
  - exact candidate_substitution_invalidates.
  - exact authentication_is_not_semantic_support.
  - exact unrelated_proof_does_not_satisfy.
  - exact challenged_premise_blocks.
  - exact revoked_premise_invalidates.
  - exact incomplete_campaign_blocks.
  - exact duplicate_credentials_do_not_satisfy_independence.
  - exact stale_transparency_blocks.
  - exact missing_archive_blocks_reconstruction.
  - exact policy_substitution_blocks.
  - exact every_derivation_is_finite.
  - exact acceptance_core_inhabited.
Qed.
