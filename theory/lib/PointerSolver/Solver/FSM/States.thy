theory States
    imports Main
begin

datatype Type = 
    Integer | 
    Bool | 
    Float | 
    Pointer | 
    PointerOfPointer | 
    Unknown

datatype Event = 
    ToInt | 
    ToBool | 
    ToFloat | 
    ToPointer | 
    ToPointerOfPointer | 
    Idle

fun transition :: "Event \<Rightarrow> Type \<Rightarrow> Type" where
    "transition ToInt Unknown = Integer" |
    "transition ToBool Unknown = Bool" |
    "transition ToFloat Unknown = Float" |
    "transition ToPointer Integer = Pointer" |
    "transition ToPointerOfPointer Pointer = PointerOfPointer" |
    "transition _ t = t"


lemma "transition ToInt Unknown = Integer" by auto
lemma "transition ToBool Unknown = Bool" by auto
lemma "transition ToFloat Unknown = Float" by auto
lemma "transition ToPointer Integer = Pointer" by auto
lemma "transition ToPointerOfPointer Pointer = PointerOfPointer" by auto
lemma "\<forall> e t. ((e \<noteq> ToInt \<and> t \<noteq> Unknown) \<and>
            (e \<noteq> ToBool \<and> t \<noteq> Unknown) \<and>
            (e \<noteq> ToFloat \<and> t \<noteq> Unknown) \<and>
            (e \<noteq> ToPointer \<and> t \<noteq> Integer) \<and>
            (e \<noteq> ToPointerOfPointer \<and> t \<noteq> Pointer)) \<longrightarrow> transition e t = t"
proof (intro conjI allI impI)
    fix e t
    assume "(e \<noteq> ToInt \<and> t \<noteq> Unknown) \<and>
            (e \<noteq> ToBool \<and> t \<noteq> Unknown) \<and>
            (e \<noteq> ToFloat \<and> t \<noteq> Unknown) \<and>
            (e \<noteq> ToPointer \<and> t \<noteq> Integer) \<and>
            (e \<noteq> ToPointerOfPointer \<and> t \<noteq> Pointer)"
    then show "transition e t = t" by (cases e) auto
qed

fun toSome :: "Type \<Rightarrow> Event" where
    "toSome Integer = ToInt" |
    "toSome Bool = ToBool" |
    "toSome Float = ToFloat" |
    "toSome Pointer = ToPointer" |
    "toSome PointerOfPointer = ToPointerOfPointer" |
    "toSome _ = Idle"

lemma "toSome Integer = ToInt" by auto
lemma "toSome Bool = ToBool" by auto
lemma "toSome Float = ToFloat" by auto
lemma "toSome Pointer = ToPointer" by auto
lemma "toSome PointerOfPointer = ToPointerOfPointer" by auto
lemma "\<forall> t. (t \<noteq> Integer \<and> 
            t \<noteq> Bool \<and>
            t \<noteq> Float \<and>
            t \<noteq> Pointer \<and>
            t \<noteq> PointerOfPointer) 
        \<longrightarrow> toSome t = Idle"
proof (intro allI impI)
    fix t
    assume "t \<noteq> Integer \<and> 
            t \<noteq> Bool \<and>
            t \<noteq> Float \<and>
            t \<noteq> Pointer \<and>
            t \<noteq> PointerOfPointer"
    then show "toSome t = Idle" by (cases t) auto
qed
