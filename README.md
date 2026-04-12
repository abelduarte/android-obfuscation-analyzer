# Android Obfuscation Analyzer

Static analyzer for Android apps that detects R8, ProGuard, minification, and
obfuscation breakage risks before release. Scan Kotlin and Java Android
projects for Gson serialization hazards, enum-name dependencies, reflection
risks, missing keep rules, WebView JavaScript interfaces, XML click handlers,
JNI entry points, and class-name-based routing that can fail after obfuscation.

Keywords: Android obfuscation analyzer, R8 analyzer, ProGuard analyzer, Android
minification, keep rules, Gson obfuscation, Kotlin static analysis, Android
release build, mobile app security, APK obfuscation, ProGuard keep rules.

## Why Use It

Android release builds often behave differently from debug builds because R8 and
ProGuard rename classes, fields, enum constants, and methods. Those changes can
break code that depends on runtime names or reflection-sensitive APIs.

Android Obfuscation Analyzer helps catch those issues before QA or production:

- Gson models without stable `@SerializedName` field names
- Transitive DTOs and enums used in serialized object graphs
- Enum `.name` contracts that may break under obfuscation
- Class-name or property-name based routing
- Reflection-sensitive code paths
- Missing, broad, or weak ProGuard/R8 keep-rule coverage
- `@Keep` usage without obvious local rule coverage
- WebView `@JavascriptInterface` risks
- XML `android:onClick` handlers
- JNI and native entry points

The tool is dependency-free and runs with Python 3.

## Install

```bash
git clone https://github.com/abelduarte/android-obfuscation-analyzer.git
cd android-obfuscation-analyzer
python3 -m py_compile android_obfuscation_analyzer.py
```

No package install is required.

## Quick Start

Scan an Android project:

```bash
python3 android_obfuscation_analyzer.py /path/to/android-project
```

Fail CI when high-severity obfuscation risks are found:

```bash
python3 android_obfuscation_analyzer.py /path/to/android-project
```

The command exits with `1` when one or more high-severity findings are detected.

## JSON Output

Use JSON for CI systems, dashboards, bots, or custom reporting:

```bash
python3 android_obfuscation_analyzer.py --format json /path/to/android-project
```

Include test sources:

```bash
python3 android_obfuscation_analyzer.py --include-tests /path/to/android-project
```

## GitHub Actions Example

```yaml
name: Android Obfuscation Analysis

on:
  pull_request:
  push:
    branches: [main]

jobs:
  obfuscation-analysis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.x"
      - name: Run Android Obfuscation Analyzer
        run: python3 android_obfuscation_analyzer.py .
```

## What It Detects

### Gson and JSON Serialization

Detects models used with Gson that may lose field compatibility after
obfuscation, especially DTOs without `@SerializedName` or targeted keep rules.

### R8 and ProGuard Keep Rules

Scans ProGuard rule files and Android build files to identify missing or weak
coverage for reflection-sensitive code and serialized models.

### Enum Name Dependencies

Flags `.name` usage and serialized enum patterns where renamed enum constants
can break protocol values, persistence, analytics, routing, or server contracts.

### Reflection and Runtime Name Lookups

Finds common reflection and name-based access patterns that depend on class,
method, or property names surviving minification.

### Android Framework Edge Cases

Looks for Android-specific obfuscation risks such as WebView JavaScript
interfaces, XML `android:onClick`, JNI/native boundaries, and runtime method
lookups.

## Exit Codes

- `0`: no high-severity findings
- `1`: one or more high-severity findings
- `2`: invalid input path or usage error

## Sample Output

```text
Android repo: /Users/example/MyAndroidApp
Release minification enabled: True
Tests included: False
Build files scanned: 3
ProGuard files scanned: 2
ProGuard files:
  - app/proguard-rules.pro
  - feature-chat/proguard-rules.pro

Findings: 5
1. [HIGH] gson: Gson model `com.example.chat.ChatMessage` has no `@SerializedName` coverage and no matching keep rule.
   evidence: app/src/main/java/com/example/chat/ConversationStore.kt:42
   evidence: app/src/main/java/com/example/chat/ChatMessage.kt
   fix: Add `@SerializedName` to the serialized properties or add a narrow keep rule for this model/package.

2. [HIGH] gson: Transitively serialized Gson model `com.example.chat.Author` has no `@SerializedName` coverage and no matching keep rule.
   evidence: app/src/main/java/com/example/chat/ConversationStore.kt:42
   evidence: app/src/main/java/com/example/chat/Author.kt
   fix: Add `@SerializedName` to the serialized properties or add a narrow keep rule for this model/package.

3. [MEDIUM] gson-enum: Transitively serialized Gson model enum `com.example.chat.MessageStatus` has no obvious keep rule for enum constant names.
   evidence: app/src/main/java/com/example/chat/ConversationStore.kt:42
   evidence: app/src/main/java/com/example/chat/ChatMessage.kt
   fix: If this enum is serialized by name, add `@SerializedName` on constants or keep enum members stable with targeted keep rules.

4. [MEDIUM] name-based-routing: Class or property names are used as runtime string values. Obfuscation can rename these identifiers and break routing, persistence, or protocol matching.
   evidence: app/src/main/java/com/example/navigation/Routes.kt:19
   fix: Prefer explicit stable string constants or add narrow keep/keepnames rules for the referenced classes or members.

5. [MEDIUM] enum-name: Enum `.name` is used in string matching or serialization-like code paths. Enum constant renaming under obfuscation can change these values.
   evidence: app/src/main/java/com/example/model/BookingType.kt:14
   fix: Use explicit stable values via a property or `@SerializedName`/mapping layer, or keep enum member names stable.
```

## CI Strategy

Use this analyzer as a fast pre-release guardrail:

1. Run it on every pull request.
2. Treat high-severity findings as release blockers.
3. Pair it with a minified release build.
4. Add runtime smoke tests for screens and APIs that rely on reflection,
   serialization, WebView, navigation, or native entry points.

## Limitations

This is a heuristic static analyzer. It does not simulate the full R8 optimizer,
does not replace Android Gradle Plugin diagnostics, and does not prove that a
release build is safe. It is designed to catch common Android obfuscation risks
early and cheaply.

For strongest coverage, use it with:

- `minifyEnabled true` release builds
- R8/ProGuard mapping review
- targeted keep rules
- runtime smoke tests against minified APKs or AABs

## License

MIT. See `LICENSE`.
