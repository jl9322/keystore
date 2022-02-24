# Add any ProGuard configurations specific to this
# extension here.

-keep public class com.jl9322.keystore.Keystore {
    public *;
 }
-keeppackagenames gnu.kawa**, gnu.expr**

-optimizationpasses 4
-allowaccessmodification
-mergeinterfacesaggressively

-repackageclasses 'com/jl9322/keystore/repack'
-flattenpackagehierarchy
-dontpreverify
-dontwarn java.lang.invoke.StringConcatFactory
