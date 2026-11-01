# --- Go core (gomobile bind) -------------------------------------------------
# The generated Java bindings are looked up and called by name from native
# code through JNI (go.Seq, go.Universe, app.privatevpnpro.mobile.*). Neither the
# classes nor their members may be renamed or removed.
-keep class go.** { *; }
-keep interface go.** { *; }
-keep class app.privatevpnpro.mobile.** { *; }
-keep interface app.privatevpnpro.mobile.** { *; }
-dontwarn go.**

# Our implementation of mobile.Callbacks is handed to Go and invoked from Go
# threads via JNI.
-keep class app.privatevpnpro.core.CoreCallbacks { *; }

# --- zxing-android-embedded ----------------------------------------------------
# Ships no consumer rules; CaptureActivity is referenced from its manifest
# (kept by AAPT rules), the decoder uses no reflection.
-dontwarn com.google.zxing.**
