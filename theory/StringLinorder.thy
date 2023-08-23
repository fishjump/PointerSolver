theory StringLinorder
  imports Main
          "HOL-Library.RBT"
begin

instantiation char :: linorder
begin

definition less_char where
"less_char a b = (of_char a < (of_char b :: nat))"

definition less_eq_char where
"less_eq_char a b = (of_char a \<le> (of_char b :: nat))"

instance by standard (auto simp add: less_char_def less_eq_char_def)

end

instantiation list :: (linorder) linorder
begin

fun less_eq_list where
  "[] \<le> _ = True" |
  "(x#xs) \<le> [] = False" |
  "(x#xs) \<le> (y#ys) = (
    if x = y then
      xs \<le> ys
    else
      x < y
  )"


fun less_list where
  "[] < ys = (ys \<noteq> [])" |
  "(x#xs) < [] = False" |
  "(x#xs) < (y#ys) = (
    if x = y then
      xs < ys
    else
      x < y
  )"

lemma [simp]:
  fixes xs ys :: "'a::linorder list"
  shows "xs \<le> ys \<or> ys \<le> xs"
proof (induct xs arbitrary: ys)
  case Nil
  then show ?case by auto
next
  case (Cons x xs)
  then show ?case by (induct ys) auto
qed

lemma [simp]:
fixes xs ys zs :: "'a::linorder list"
shows "xs \<le> ys \<Longrightarrow> ys \<le> zs \<Longrightarrow> xs \<le> zs"
proof (induct xs arbitrary: ys zs)
  case Nil
  then show ?case by auto
next
  case (Cons x xs)
  then show ?case
  proof (induct ys arbitrary: zs)
    case Nil
    then show ?case by auto
  next
    case (Cons y ys)
    then show ?case by (induct zs) auto
  qed
qed

lemma [simp]:
fixes xs ys :: "'a::linorder list"
shows "xs \<le> ys \<Longrightarrow> ys \<le> xs \<Longrightarrow> xs = ys"
proof -
  assume "xs \<le> ys" and "ys \<le> xs"
  then show "xs = ys"
  proof (induct xs arbitrary: ys)
    case Nil
    then show ?case by (induct ys) auto
  next
    case (Cons x xs)
    then show ?case by (induct ys) auto
  qed
qed

lemma [simp]:
fixes xs ys :: "'a::linorder list"
shows "xs < ys = (xs \<le> ys \<and> \<not> ys \<le> xs)"
proof (induct xs)
  case Nil
  then show ?case by auto
next
  case (Cons x xs)
  then show ?case by (induct ys) auto
qed

instance
proof
  fix xs ys zs :: "'a::linorder list"
  show "xs \<le> xs" by (induct xs) auto
  show "xs \<le> ys \<Longrightarrow> ys \<le> zs \<Longrightarrow> xs \<le> zs" by auto
  show "xs \<le> ys \<Longrightarrow> ys \<le> xs \<Longrightarrow> xs = ys" by auto
  show "xs \<le> ys \<or> ys \<le> xs" by auto
  show "xs < ys = (xs \<le> ys \<and> \<not> ys \<le> xs)" by auto
qed

end


instantiation prod :: (linorder, linorder) linorder
begin

fun less_eq_prod :: "'a \<times> 'b \<Rightarrow> 'a \<times> 'b \<Rightarrow> bool" where
  "(a1, b1) \<le> (a2, b2) \<longleftrightarrow> (a1 < a2) \<or> (a1 = a2 \<and> b1 \<le> b2)"

fun less_prod :: "'a \<times> 'b \<Rightarrow> 'a \<times> 'b \<Rightarrow> bool" where
  "(a1, b1) < (a2, b2) \<longleftrightarrow> (a1 < a2) \<or> (a1 = a2 \<and> b1 < b2)"

instance by (standard, auto)

end

end