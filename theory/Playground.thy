theory Playground
    imports Main
begin

lemma finite_elements:
  fixes l :: "'a list" and n :: "nat"
  assumes "n < length l"
  shows "finite {i. i < n}"
proof -
  have "{i. i < n} \<subseteq> {0..<n}" by auto
  then show ?thesis using finite_atLeastLessThan by auto
qed

fun count :: "string => string list => nat" where
    "count _ [] = 0" |
    "count s (x#xs) = (if s = x then 1 else 0) + count s xs"

fun find_element :: "(nat \<Rightarrow> bool) \<Rightarrow> nat list \<Rightarrow> nat option" where
  "find_element _ [] = None" |
  "find_element P (x#xs) = (if P x then Some x else find_element P xs)"

lemma termination_find_element: "\<exists> result. find_element P lst = result"
by (induction lst) auto

lemma correctness_find_element:
  "\<exists> x \<in> set lst. P x \<Longrightarrow> \<exists> x. find_element P lst = Some x \<and> P x"
proof (induction lst)
  case Nil
  then show ?case by simp
next
  case (Cons a lst)
  then show ?case
  proof (cases "P a")
    case True
    then show ?thesis by simp
  next
    case False
    with Cons.IH Cons.prems show ?thesis
      by (metis find_element.simps(2) list.set_intros(2))
  qed
qed


end