# Android Obfuscation Analyzer

Static analyzer for Android projects that detects obfuscation and R8/ProGuard breakage risks before release.

It focuses on patterns that commonly fail after minification, such as:

- Gson models without stable field names
- transitive DTOs and enums used in serialized object graphs
- enum `.name` string contracts
- class-name-based routing and runtime name lookups
- reflection-sensitive code paths
- missing or weak keep-rule coverage
- `@Keep` usage without obvious local rule coverage
- WebView JavaScript interface risks
- XML `android:onClick` handlers
- JNI/native entry points

## Install

No dependencies are required beyond Python 3.

```bash
git clone https://github.com/abelduarte/android-obfuscation-analyzer.git
cd android-obfuscation-analyzer
python3 -m py_compile android_obfuscation_analyzer.py
```

## Usage

Run against any Android repo:

```bash
python3 android_obfuscation_analyzer.py /path/to/android-project
```

JSON output:

```bash
python3 android_obfuscation_analyzer.py --format json /path/to/android-project
```

Include test sources:

```bash
python3 android_obfuscation_analyzer.py --include-tests /path/to/android-project
```

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

## Notes

This tool is heuristic-based. It is useful for catching common pre-release obfuscation risks early, but it is not a full R8 semantic analyzer.

For strongest coverage, use it together with a minified release build and runtime smoke tests.
