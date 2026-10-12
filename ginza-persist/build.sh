#!/bin/sh
set -eu

project_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH='' cd -- "$project_dir/.." && pwd)
sdk_root=${ANDROID_SDK_ROOT:?Set ANDROID_SDK_ROOT to an Android SDK directory}
java_home=${JAVA_HOME:?Set JAVA_HOME to a JDK directory}
build_tools=${ANDROID_BUILD_TOOLS:-$sdk_root/build-tools/35.0.0}
android_jar=${ANDROID_JAR:-$sdk_root/platforms/android-36/android.jar}
output=${1:-$repo_dir/ginza-root-autostart.apk}
keystore=${GINZA_KEYSTORE:-$project_dir/debug.keystore}
zig=${ZIG:-zig}
javac=$java_home/bin/javac
jar=$java_home/bin/jar
keytool=$java_home/bin/keytool

for tool in aapt2 d8 apksigner zipalign; do
  if [ ! -x "$build_tools/$tool" ]; then
    echo "Missing $build_tools/$tool" >&2
    exit 1
  fi
done
for tool in "$javac" "$jar" "$keytool"; do
  if [ ! -x "$tool" ]; then
    echo "Missing $tool" >&2
    exit 1
  fi
done
if [ ! -f "$android_jar" ]; then
  echo "Missing $android_jar" >&2
  exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
mkdir -p "$work/classes" "$work/dex" "$work/gen" \
  "$work/payload/lib/armeabi-v7a"

ZIG="$zig" "$repo_dir/tools/build_ginza_mali_38181.sh" \
  "$work/payload/lib/armeabi-v7a/libginzaroot.so"
ANDROID_SDK_ROOT="$sdk_root" "$project_dir/build_dropbear.sh" \
  "$work/payload/lib/armeabi-v7a/libdropbearmulti.so"

"$build_tools/aapt2" compile \
  --dir "$project_dir/res" \
  -o "$work/resources.zip"
"$build_tools/aapt2" link \
  -I "$android_jar" \
  --manifest "$project_dir/AndroidManifest.xml" \
  --min-sdk-version 30 \
  --target-sdk-version 30 \
  --version-code 1 \
  --version-name 1.0 \
  --java "$work/gen" \
  -o "$work/base.apk" \
  "$work/resources.zip"

find "$project_dir/src" -name '*.java' -print > "$work/sources.txt"
find "$work/gen" -name '*.java' -print >> "$work/sources.txt"
"$javac" \
  -source 8 \
  -target 8 \
  -Xlint:-options \
  -bootclasspath "$android_jar" \
  -d "$work/classes" \
  @"$work/sources.txt"
"$jar" --create --file "$work/classes.jar" -C "$work/classes" .
"$build_tools/d8" \
  --min-api 30 \
  --output "$work/dex" \
  "$work/classes.jar"

cp "$work/base.apk" "$work/unsigned.apk"
(cd "$work/dex" && zip -q -u "$work/unsigned.apk" classes.dex)
(cd "$work/payload" && zip -q -u -r "$work/unsigned.apk" lib)
"$build_tools/zipalign" -f -p 4 "$work/unsigned.apk" "$work/aligned.apk"

if [ ! -f "$keystore" ]; then
  "$keytool" -genkeypair \
    -keystore "$keystore" \
    -storepass android \
    -alias androiddebugkey \
    -keypass android \
    -dname 'CN=Android Debug,O=Android,C=US' \
    -keyalg RSA \
    -keysize 2048 \
    -validity 10000 \
    -noprompt >/dev/null
fi

"$build_tools/apksigner" sign \
  --ks "$keystore" \
  --ks-key-alias androiddebugkey \
  --ks-pass pass:android \
  --key-pass pass:android \
  --out "$output" \
  "$work/aligned.apk"
"$build_tools/apksigner" verify --verbose "$output"
sha256sum "$output"
