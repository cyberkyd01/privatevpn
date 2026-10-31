VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
GOFLAGS := -trimpath
DIST := dist

ANDROID_HOME ?= $(HOME)/Library/Android/sdk
# gomobile is tested with NDK 27/28 (§15.4); prefer the newest of those, else any installed NDK.
ANDROID_NDK_HOME ?= $(or $(lastword $(sort $(wildcard $(ANDROID_HOME)/ndk/27.* $(ANDROID_HOME)/ndk/28.*))),$(lastword $(sort $(wildcard $(ANDROID_HOME)/ndk/*))))
# Gradle/AGP need JDK 17–21; a newer system JDK (JAVA_HOME) is not supported, so the
# Android targets use ANDROID_JAVA_HOME (default: Android Studio's bundled JDK 21).
STUDIO_JBR := /Applications/Android Studio.app/Contents/jbr/Contents/Home
ANDROID_JAVA_HOME ?= $(if $(shell test -x "$(STUDIO_JBR)/bin/java" && echo y),$(STUDIO_JBR),$(JAVA_HOME))
# versionName/versionCode from a vMAJOR.MINOR.PATCH tag; anything else builds as 1.0.0.
APP_VERSION := $(shell echo '$(VERSION)' | sed -nE 's/^v?([0-9]+\.[0-9]+\.[0-9]+)$$/\1/p')
GRADLE_VERSION_ARG := $(if $(APP_VERSION),-PappVersion=$(APP_VERSION))

.PHONY: all test vet desktop windows linux macos core-aar android android-debug clean

all: test windows linux macos android

test:
	go test -race ./...

vet:
	go vet ./...
	GOOS=windows go vet ./...
	GOOS=linux go vet ./...

desktop:
	go run ./cmd/privatevpn

windows:
	cd cmd/privatevpn && go tool go-winres make --arch amd64,arm64 --in ../../build/windows/winres.json
	for arch in amd64 arm64; do \
	  CGO_ENABLED=0 GOOS=windows GOARCH=$$arch go build $(GOFLAGS) -ldflags "$(LDFLAGS) -H windowsgui" -o $(DIST)/windows-$$arch/privatevpn.exe ./cmd/privatevpn && \
	  bash build/windows/fetch-wintun.sh $$arch $(DIST)/windows-$$arch ; \
	done

linux:
	for arch in amd64 arm64; do \
	  CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST)/linux-$$arch/privatevpn ./cmd/privatevpn ; \
	done

macos:
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST)/macos/privatevpn-arm64 ./cmd/privatevpn
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST)/macos/privatevpn-amd64 ./cmd/privatevpn
	lipo -create -output $(DIST)/macos/privatevpn $(DIST)/macos/privatevpn-arm64 $(DIST)/macos/privatevpn-amd64
	bash build/macos/make-app.sh $(DIST)/macos/privatevpn $(VERSION) $(DIST)/macos

# gomobile bind looks up gobind on PATH: build the go.mod-pinned one into bin/ (git-ignored)
# instead of requiring `gomobile init` / a global install.
GOBIND_DIR := $(CURDIR)/bin/gomobile

core-aar:
	mkdir -p android/app/libs "$(GOBIND_DIR)"
	go build -o "$(GOBIND_DIR)/gobind" golang.org/x/mobile/cmd/gobind
	PATH="$(GOBIND_DIR):$$PATH" ANDROID_HOME="$(ANDROID_HOME)" ANDROID_NDK_HOME="$(ANDROID_NDK_HOME)" JAVA_HOME="$(ANDROID_JAVA_HOME)" \
	  go tool gomobile bind -target android/arm64,android/arm,android/amd64 -androidapi 26 \
	  -javapkg app.privatevpn -trimpath -ldflags "$(LDFLAGS)" -o android/app/libs/core.aar ./mobile

# Signed when ANDROID_KEYSTORE_FILE (+ _PASSWORD, ANDROID_KEY_ALIAS, ANDROID_KEY_PASSWORD) is set,
# otherwise Gradle produces app-release-unsigned.apk.
android: core-aar
	cd android && JAVA_HOME="$(ANDROID_JAVA_HOME)" ANDROID_HOME="$(ANDROID_HOME)" ./gradlew --no-daemon assembleRelease $(GRADLE_VERSION_ARG)
	mkdir -p $(DIST)/android
	if [ -f android/app/build/outputs/apk/release/app-release.apk ]; then \
	  cp android/app/build/outputs/apk/release/app-release.apk $(DIST)/android/privatevpn-android.apk ; \
	else \
	  cp android/app/build/outputs/apk/release/app-release-unsigned.apk $(DIST)/android/privatevpn-android-unsigned.apk ; \
	fi

android-debug: core-aar
	cd android && JAVA_HOME="$(ANDROID_JAVA_HOME)" ANDROID_HOME="$(ANDROID_HOME)" ./gradlew --no-daemon assembleDebug $(GRADLE_VERSION_ARG)

clean:
	rm -rf $(DIST) android/app/libs android/app/build cmd/privatevpn/*.syso
