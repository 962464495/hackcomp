ANDROID_NDK_HOME=$(HOME)/Disk1/Android/Sdk/ndk/27.0.12077973/
export ANDROID_NDK_HOME

build-ndk-dev:
	cargo ndk -t arm64-v8a b

test: build-ndk-dev
	adb push ./target/aarch64-linux-android/debug/hackcomp /data/local/tmp
	adb shell "RUST_LOG=trace /data/local/tmp/hackcomp"

