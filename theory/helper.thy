theory helper
    imports Main
begin

fun init :: "'a list \<Rightarrow> 'a list" where
    "init ([]) = []" |
    "init ([x]) = []" |
    "init (x#xs) = x#(init xs)"

fun last :: "'a list \<Rightarrow> 'a option" where
    "last ([]) = None" |
    "last ([x]) = Some x" |
    "last (x#xs) = last xs"

fun splitOn :: "'a list \<Rightarrow> 'a list \<Rightarrow> 'a list list" where
    "splitOn xs [] = [[]]" |
    "splitOn [] ys = [ys]" |
    "splitOn xs (y#ys) = (if List.member xs y then [] else [[]])"

value "splitOn [a,b,c] [b,c,d]"

end