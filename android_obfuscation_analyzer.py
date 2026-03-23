#!/usr/bin/env python3
"""
Static analyzer for Android obfuscation risks.

The goal is not to simulate R8. It flags code patterns that commonly break once
minification/obfuscation is enabled so teams can add keep rules or annotations
before release builds fail in QA or production.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


SOURCE_EXTENSIONS = {".kt", ".java"}
XML_EXTENSIONS = {".xml"}
IGNORED_DIR_NAMES = {
    ".git",
    ".gradle",
    ".idea",
    "build",
    "out",
    "generated",
    ".kotlin",
}
GSON_EXCLUDED_TYPES = {
    "Any",
    "Unit",
    "JsonObject",
    "JsonArray",
    "JsonElement",
    "List",
    "MutableList",
    "Set",
    "MutableSet",
    "Map",
    "MutableMap",
    "String",
    "Int",
    "Long",
    "Double",
    "Float",
    "Boolean",
    "UUID",
    "Instant",
    "Throwable",
}


@dataclass
class Finding:
    severity: str
    category: str
    message: str
    evidence: list[str] = field(default_factory=list)
    recommendation: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "severity": self.severity,
            "category": self.category,
            "message": self.message,
            "evidence": list(self.evidence),
            "recommendation": self.recommendation,
        }


@dataclass
class PropertyInfo:
    name: str
    visibility: str | None
    transient: bool
    type_names: list[str]


@dataclass
class ClassInfo:
    simple_name: str
    fqcn: str
    path: Path
    content: str
    properties: list[PropertyInfo]
    serialized_fields: set[str]
    keep_annotated: bool
    is_enum: bool


def is_test_source(path: Path) -> bool:
    normalized = str(path).replace("\\", "/")
    return "/src/test/" in normalized or "/src/androidTest/" in normalized


def iter_files(root: Path, extensions: set[str], *, include_tests: bool = False) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in IGNORED_DIR_NAMES for part in path.parts):
            continue
        if path.suffix in extensions:
            if not include_tests and is_test_source(path):
                continue
            yield path


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="ignore")


def rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def line_number_for_match(content: str, match: re.Match[str]) -> int:
    return content.count("\n", 0, match.start()) + 1


def format_location(path: Path, root: Path, line: int | None = None) -> str:
    base = rel(path, root)
    return f"{base}:{line}" if line else base


def collect_build_files(root: Path) -> list[Path]:
    result = []
    for candidate in ("build.gradle", "build.gradle.kts"):
        result.extend(p for p in root.rglob(candidate) if "build" not in p.parts)
    return sorted(set(result))


def collect_proguard_files(root: Path) -> list[Path]:
    patterns = (
        "*proguard*.pro",
        "*consumer-rules.pro",
        "*rules.pro",
    )
    found: set[Path] = set()
    for pattern in patterns:
        found.update(p for p in root.rglob(pattern) if "build" not in p.parts)
    return sorted(found)


def has_release_minification(build_files: list[Path]) -> tuple[bool, list[str]]:
    evidence: list[str] = []
    enabled = False
    release_block = re.compile(r"release\s*\{(?P<body>.*?)\n\s*\}", re.DOTALL)
    minify_pattern = re.compile(r"(?:isMinifyEnabled|minifyEnabled)\s*=\s*true")
    for build_file in build_files:
        content = read_text(build_file)
        for match in release_block.finditer(content):
            body = match.group("body")
            if minify_pattern.search(body):
                enabled = True
                evidence.append(format_location(build_file, build_file.parent.parent if build_file.parent.parent.exists() else build_file.parent, line_number_for_match(content, match)))
        for match in minify_pattern.finditer(content):
            enabled = True
            evidence.append(format_location(build_file, build_file.parent.parent if build_file.parent.parent.exists() else build_file.parent, line_number_for_match(content, match)))
    return enabled, sorted(set(evidence))


def build_class_index(root: Path, *, include_tests: bool = False) -> dict[str, list[ClassInfo]]:
    class_index: dict[str, list[ClassInfo]] = {}
    package_pattern = re.compile(r"^\s*package\s+([A-Za-z0-9_.]+)", re.MULTILINE)
    class_pattern = re.compile(
        r"(?m)^\s*(?:@[\w.]+\s*)*(?:(?:public|internal|private|protected|data|sealed|open|abstract|final)\s+)*(class|interface|object|enum\s+class)\s+([A-Z][A-Za-z0-9_]*)"
    )
    property_pattern = re.compile(
        r"(?m)^\s*(?P<annotations>(?:@[\w.()\"{},\s]+\s+)*)"
        r"(?:(?P<visibility>private|public|internal|protected)\s+)?"
        r"(?:override\s+)?(?:lateinit\s+)?(?:val|var)\s+(?P<name>[a-zA-Z_][A-Za-z0-9_]*)\s*:\s*(?P<type>[^=\n,]+)"
    )
    serialized_field_pattern = re.compile(r'@SerializedName\(".*?"\)\s*(?:@[\w.]+\s*)*(?:private|public|internal|protected)?\s*(?:override\s+)?(?:lateinit\s+)?(?:val|var)\s+([a-zA-Z_][A-Za-z0-9_]*)')
    keep_pattern = re.compile(r"@Keep\b")

    for source_file in iter_files(root, SOURCE_EXTENSIONS, include_tests=include_tests):
        content = read_text(source_file)
        package_match = package_pattern.search(content)
        package_name = package_match.group(1) if package_match else ""
        matches = list(class_pattern.finditer(content))
        if not matches:
            continue
        for index, match in enumerate(matches):
            class_name = match.group(2)
            segment_end = matches[index + 1].start() if index + 1 < len(matches) else len(content)
            segment = content[match.start():segment_end]
            property_source = segment.split("{", 1)[0]
            properties = [
                PropertyInfo(
                    name=property_match.group("name"),
                    visibility=property_match.group("visibility"),
                    transient="@Transient" in (property_match.group("annotations") or ""),
                    type_names=extract_model_type_names(property_match.group("type")),
                )
                for property_match in property_pattern.finditer(property_source)
            ]
            serialized_fields = set(serialized_field_pattern.findall(property_source))
            keep_annotated = bool(keep_pattern.search(segment))
            is_enum = match.group(1) == "enum class"
            fqcn = f"{package_name}.{class_name}" if package_name else class_name
            info = ClassInfo(
                simple_name=class_name,
                fqcn=fqcn,
                path=source_file,
                content=segment,
                properties=properties,
                serialized_fields=serialized_fields,
                keep_annotated=keep_annotated,
                is_enum=is_enum,
            )
            class_index.setdefault(class_name, []).append(info)
    return class_index


def extract_model_type_names(type_expression: str) -> list[str]:
    cleaned = re.sub(r"\b(?:out|in)\b", " ", type_expression)
    names = re.findall(r"\b([A-Z][A-Za-z0-9_]*)\b", cleaned)
    return [name for name in names if name not in GSON_EXCLUDED_TYPES and name != "TypeToken"]


def parse_gson_candidate_types(root: Path, *, include_tests: bool = False) -> list[tuple[str, str, Path]]:
    patterns = [
        re.compile(r"\bfromJson\([^,\n]+,\s*([A-Z][A-Za-z0-9_]*(?:<[A-Z][A-Za-z0-9_]*>)?)::class\.java\)"),
        re.compile(r"\b(?:responseType|successResponseType|errorResponseType)\s*=\s*([A-Z][A-Za-z0-9_]*(?:<[A-Z][A-Za-z0-9_]*>)?)::class\.java"),
        re.compile(r"TypeToken<([^>]+)>"),
    ]
    candidates: list[tuple[str, str, Path]] = []
    for source_file in iter_files(root, SOURCE_EXTENSIONS, include_tests=include_tests):
        content = read_text(source_file)
        if not any(token in content for token in ("Gson", "fromJson", "responseType", "successResponseType", "errorResponseType")):
            continue
        for pattern in patterns:
            for match in pattern.finditer(content):
                raw_type = match.group(1)
                for type_name in extract_model_type_names(raw_type.replace("Array<", "").replace(">", "")):
                    candidates.append((type_name, format_location(source_file, root, line_number_for_match(content, match)), source_file))
    return candidates


def resolve_class_infos(type_name: str, source_file: Path, class_index: dict[str, list[ClassInfo]]) -> list[ClassInfo]:
    matches = class_index.get(type_name, [])
    if len(matches) <= 1:
        return matches

    content = read_text(source_file)
    package_match = re.search(r"^\s*package\s+([A-Za-z0-9_.]+)", content, re.MULTILINE)
    package_name = package_match.group(1) if package_match else ""
    import_matches = re.findall(rf"^\s*import\s+([A-Za-z0-9_.]*\.{re.escape(type_name)})\s*$", content, re.MULTILINE)
    imported = set(import_matches)

    prioritized = [item for item in matches if item.fqcn in imported]
    if prioritized:
        return prioritized

    if imported:
        path_name_matches = [
            item for item in matches
            if any(item.path.stem in imported_name for imported_name in imported)
        ]
        if path_name_matches:
            return path_name_matches

    same_package = [item for item in matches if item.fqcn.startswith(package_name + ".")]
    if same_package:
        return same_package

    same_file = [item for item in matches if item.path == source_file]
    if same_file:
        return same_file

    return matches


def collect_transitive_class_infos(root_infos: list[ClassInfo], class_index: dict[str, list[ClassInfo]]) -> list[ClassInfo]:
    queue = list(root_infos)
    visited: set[str] = set()
    result: list[ClassInfo] = []

    while queue:
        class_info = queue.pop(0)
        if class_info.fqcn in visited:
            continue
        visited.add(class_info.fqcn)
        result.append(class_info)

        for prop in class_info.properties:
            for type_name in prop.type_names:
                for nested_info in class_index.get(type_name, []):
                    if nested_info.fqcn not in visited:
                        queue.append(nested_info)

    return result


def find_proguard_coverage(proguard_text: str, fqcn: str, package_name: str) -> bool:
    escaped_fqcn = re.escape(fqcn)
    escaped_pkg_glob = re.escape(package_name + ".") + r"\*\*"
    patterns = [
        rf"-keep[^\n]*class\s+{escaped_fqcn}\b",
        rf"-keepclassmembers[^\n]*class\s+{escaped_fqcn}\b",
        rf"-keep[^\n]*class\s+{escaped_pkg_glob}",
        rf"-keepclassmembers[^\n]*class\s+{escaped_pkg_glob}",
    ]
    return any(re.search(pattern, proguard_text) for pattern in patterns)


def has_keep_rule(proguard_text: str, snippets: list[str]) -> bool:
    return all(snippet in proguard_text for snippet in snippets)


def unique_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    result: list[Finding] = []
    for finding in findings:
        key = json.dumps(
            {
                "severity": finding.severity,
                "category": finding.category,
                "message": finding.message,
                "evidence": sorted(set(finding.evidence)),
                "recommendation": finding.recommendation,
            },
            sort_keys=True,
        )
        if key in seen:
            continue
        seen.add(key)
        finding.evidence = sorted(set(finding.evidence))
        result.append(finding)
    return result


def analyze_repo(root: Path, *, include_tests: bool = False) -> tuple[dict[str, object], list[Finding]]:
    build_files = collect_build_files(root)
    proguard_files = collect_proguard_files(root)
    proguard_text = "\n".join(read_text(path) for path in proguard_files)
    minify_enabled, minify_evidence = has_release_minification(build_files)
    class_index = build_class_index(root, include_tests=include_tests)

    findings: list[Finding] = []

    summary = {
        "root": str(root),
        "build_files": [rel(path, root) for path in build_files],
        "proguard_files": [rel(path, root) for path in proguard_files],
        "release_minification_enabled": minify_enabled,
        "tests_included": include_tests,
    }

    if not minify_enabled:
        findings.append(
            Finding(
                severity="info",
                category="build",
                message="Release minification does not appear to be enabled. Obfuscation risks may stay hidden until R8 is turned on.",
                evidence=minify_evidence,
                recommendation="Enable `isMinifyEnabled = true` for a release-like build in CI if you want this analyzer to guard real obfuscation behavior.",
            )
        )

    gson_candidates = parse_gson_candidate_types(root, include_tests=include_tests)
    gson_evidence_by_type: dict[str, list[str]] = {}
    for type_name, location, source_file in gson_candidates:
        gson_evidence_by_type.setdefault(f"{type_name}|{source_file}", []).append(location)

    for typed_key, evidence in sorted(gson_evidence_by_type.items()):
        type_name, source_file_str = typed_key.split("|", 1)
        source_file = Path(source_file_str)
        root_class_infos = resolve_class_infos(type_name, source_file, class_index)
        if not root_class_infos:
            findings.append(
                Finding(
                    severity="medium",
                    category="gson",
                    message=f"Gson appears to deserialize `{type_name}`, but the class declaration was not found in source.",
                    evidence=sorted(set(evidence)),
                    recommendation="If this type lives in another module or generated source, confirm that its fields are annotated or protected by keep rules.",
                )
            )
            continue

        transitive_class_infos = collect_transitive_class_infos(root_class_infos, class_index)
        root_fqcns = {info.fqcn for info in root_class_infos}

        for class_info in transitive_class_infos:
            non_synthetic_props = [
                prop for prop in class_info.properties
                if not prop.name.startswith("_")
                and prop.name not in {"Companion"}
                and prop.visibility != "private"
                and not prop.transient
            ]
            unannotated_props = [prop.name for prop in non_synthetic_props if prop.name not in class_info.serialized_fields]
            package_name = class_info.fqcn.rsplit(".", 1)[0] if "." in class_info.fqcn else class_info.fqcn
            has_direct_keep = find_proguard_coverage(proguard_text, class_info.fqcn, package_name)
            is_root = class_info.fqcn in root_fqcns
            context_message = "Gson model" if is_root else "Transitively serialized Gson model"

            if class_info.keep_annotated or has_direct_keep:
                continue

            if class_info.is_enum:
                findings.append(
                    Finding(
                        severity="medium",
                        category="gson-enum",
                        message=f"{context_message} enum `{class_info.fqcn}` has no obvious keep rule for enum constant names.",
                        evidence=sorted(set(evidence + [format_location(class_info.path, root)])),
                        recommendation="If this enum is serialized by name, add `@SerializedName` on constants or keep enum members stable with targeted keep rules.",
                    )
                )
                continue

            if non_synthetic_props and len(unannotated_props) == len(non_synthetic_props):
                findings.append(
                    Finding(
                        severity="high",
                        category="gson",
                        message=f"{context_message} `{class_info.fqcn}` has no `@SerializedName` coverage and no matching keep rule.",
                        evidence=sorted(set(evidence + [format_location(class_info.path, root)])),
                        recommendation="Add `@SerializedName` to the serialized properties or add a narrow keep rule for this model/package.",
                    )
                )
            elif unannotated_props:
                findings.append(
                    Finding(
                        severity="medium",
                        category="gson",
                        message=f"{context_message} `{class_info.fqcn}` mixes annotated and unannotated properties, which can break after field obfuscation.",
                        evidence=sorted(set(evidence + [format_location(class_info.path, root)])),
                        recommendation="Annotate the remaining serialized properties with `@SerializedName` or keep class members for this type.",
                    )
                )

    js_interface_hits: list[str] = []
    for source_file in iter_files(root, SOURCE_EXTENSIONS, include_tests=include_tests):
        content = read_text(source_file)
        for pattern in (r"@JavascriptInterface", r"\baddJavascriptInterface\s*\("):
            for match in re.finditer(pattern, content):
                js_interface_hits.append(format_location(source_file, root, line_number_for_match(content, match)))
    if js_interface_hits and not has_keep_rule(proguard_text, ["@android.webkit.JavascriptInterface <methods>;"]):
        findings.append(
            Finding(
                severity="high",
                category="webview-js",
                message="WebView JavaScript interface methods were found, but there is no obvious keep rule for `@JavascriptInterface` methods.",
                evidence=sorted(set(js_interface_hits)),
                recommendation="Add `-keepclassmembers class * { @android.webkit.JavascriptInterface <methods>; }`.",
            )
        )

    onclick_hits: list[str] = []
    for xml_file in iter_files(root, XML_EXTENSIONS, include_tests=include_tests):
        content = read_text(xml_file)
        for match in re.finditer(r'android:onClick="([^"]+)"', content):
            onclick_hits.append(format_location(xml_file, root, line_number_for_match(content, match)))
    if onclick_hits and "public void *(android.view.View);" not in proguard_text:
        findings.append(
            Finding(
                severity="high",
                category="xml-onclick",
                message="XML `android:onClick` handlers were found, but there is no matching keep rule for callback method names.",
                evidence=sorted(set(onclick_hits)),
                recommendation="Add `-keepclassmembers class * { public void *(android.view.View); }` or replace XML callbacks with explicit listeners.",
            )
        )

    native_hits: list[str] = []
    for source_file in iter_files(root, SOURCE_EXTENSIONS, include_tests=include_tests):
        content = read_text(source_file)
        for match in re.finditer(r"\b(?:external|native)\s+fun\s+([A-Za-z_][A-Za-z0-9_]*)", content):
            native_hits.append(format_location(source_file, root, line_number_for_match(content, match)))
    if native_hits and "-keepclasseswithmembernames class * {" not in proguard_text:
        findings.append(
            Finding(
                severity="high",
                category="jni",
                message="Native/JNI entry points were found, but there is no obvious keepnames rule for native methods.",
                evidence=sorted(set(native_hits)),
                recommendation="Add a targeted native keep rule, for example `-keepclasseswithmembernames class * { native <methods>; }`.",
            )
        )

    reflection_hits: list[str] = []
    reflection_strings: list[str] = []
    reflection_pattern = re.compile(r'Class\.forName\(\s*"([^"]+)"\s*\)')
    named_reflection_hits: list[str] = []
    dynamic_reflection_pattern = re.compile(
        r"\b(?:getDeclaredMethod|getMethod|getDeclaredField|getField|ServiceLoader\.load|Proxy\.newProxyInstance|DexClassLoader|PathClassLoader)\b"
    )
    for source_file in iter_files(root, SOURCE_EXTENSIONS, include_tests=include_tests):
        content = read_text(source_file)
        for match in reflection_pattern.finditer(content):
            reflection_hits.append(format_location(source_file, root, line_number_for_match(content, match)))
            reflection_strings.append(match.group(1))
        for match in dynamic_reflection_pattern.finditer(content):
            named_reflection_hits.append(format_location(source_file, root, line_number_for_match(content, match)))
    if reflection_hits:
        missing_coverage = []
        for class_name in reflection_strings:
            package_name = class_name.rsplit(".", 1)[0] if "." in class_name else class_name
            if not find_proguard_coverage(proguard_text, class_name, package_name):
                missing_coverage.append(class_name)
        if missing_coverage:
            findings.append(
                Finding(
                    severity="high",
                    category="reflection",
                    message="String-based reflection was found without matching keep coverage for at least one target class.",
                    evidence=sorted(set(reflection_hits)),
                    recommendation="Add targeted `-keep` or `-keepnames` rules for reflected classes: " + ", ".join(sorted(set(missing_coverage))),
                )
            )
    if named_reflection_hits:
        findings.append(
            Finding(
                severity="medium",
                category="reflection",
                message="Reflection or dynamic class loading APIs were found. These code paths often need explicit keep rules when names are looked up dynamically.",
                evidence=sorted(set(named_reflection_hits)),
                recommendation="Review these call sites and add targeted `-keep` or `-keepclassmembers` rules for any names accessed reflectively.",
            )
        )

    class_name_hits: list[str] = []
    class_name_pattern = re.compile(
        r"::class\.(?:qualifiedName|simpleName)|::class\.java\.name|\bjavaClass\.(?:name|simpleName)\b|::[a-zA-Z_][A-Za-z0-9_]*\.name"
    )
    for source_file in iter_files(root, SOURCE_EXTENSIONS, include_tests=include_tests):
        content = read_text(source_file)
        for match in class_name_pattern.finditer(content):
            class_name_hits.append(format_location(source_file, root, line_number_for_match(content, match)))
    if class_name_hits:
        findings.append(
            Finding(
                severity="medium",
                category="name-based-routing",
                message="Class or property names are used as runtime string values. Obfuscation can rename these identifiers and break routing, persistence, or protocol matching.",
                evidence=sorted(set(class_name_hits)),
                recommendation="Prefer explicit stable string constants or add narrow keep/keepnames rules for the referenced classes or members.",
            )
        )

    enum_name_hits: list[str] = []
    enum_names = {info.simple_name for class_infos in class_index.values() for info in class_infos if any(item.is_enum for item in class_infos)}
    enum_constant_name_patterns = [
        re.compile(rf"\b{re.escape(enum_name)}\.[A-Z][A-Za-z0-9_]*\.name\b")
        for enum_name in sorted(enum_names)
    ]
    enum_entries_name_pattern = re.compile(r"\bentries\.(?:find|first|firstOrNull|single|singleOrNull|filter)\s*\{[^}]*\.name\b", re.DOTALL)
    for source_file in iter_files(root, SOURCE_EXTENSIONS, include_tests=include_tests):
        content = read_text(source_file)
        for pattern in enum_constant_name_patterns:
            for match in pattern.finditer(content):
                enum_name_hits.append(format_location(source_file, root, line_number_for_match(content, match)))
        for match in enum_entries_name_pattern.finditer(content):
            enum_name_hits.append(format_location(source_file, root, line_number_for_match(content, match)))
    if enum_name_hits:
        findings.append(
            Finding(
                severity="medium",
                category="enum-name",
                message="Enum `.name` is used in string matching or serialization-like code paths. Enum constant renaming under obfuscation can change these values.",
                evidence=sorted(set(enum_name_hits)),
                recommendation="Use explicit stable values via a property or `@SerializedName`/mapping layer, or keep enum member names stable.",
            )
        )

    keep_annotated_classes = [
        info for class_infos in class_index.values() for info in class_infos if info.keep_annotated
    ]
    if keep_annotated_classes:
        keep_rule_present = "@androidx.annotation.Keep" in proguard_text or "class *" in proguard_text and "@androidx.annotation.Keep" in proguard_text
        if not keep_rule_present:
            findings.append(
                Finding(
                    severity="medium",
                    category="keep-annotation",
                    message="`@Keep` is used in source, but there is no obvious keep rule for `androidx.annotation.Keep` in local ProGuard files.",
                    evidence=sorted({format_location(info.path, root) for info in keep_annotated_classes[:10]}),
                    recommendation="Confirm consumer rules already honor `@Keep`, or add a rule such as `-keep @androidx.annotation.Keep class * { *; }` and matching member rules.",
                )
            )

    if not proguard_files and minify_enabled:
        findings.append(
            Finding(
                severity="high",
                category="proguard",
                message="Release minification is enabled, but no ProGuard/R8 rules file was found.",
                recommendation="Add an app-specific rules file and wire it into the release build.",
            )
        )

    findings = unique_findings(findings)
    findings = sorted(findings, key=lambda item: ("high", "medium", "info").index(item.severity))
    summary["finding_counts"] = {
        "high": sum(1 for finding in findings if finding.severity == "high"),
        "medium": sum(1 for finding in findings if finding.severity == "medium"),
        "info": sum(1 for finding in findings if finding.severity == "info"),
        "total": len(findings),
    }
    return summary, findings


def print_report(summary: dict[str, object], findings: list[Finding]) -> None:
    print(f"Android repo: {summary['root']}")
    print(f"Release minification enabled: {summary['release_minification_enabled']}")
    print(f"Tests included: {summary['tests_included']}")
    build_files = summary["build_files"]
    proguard_files = summary["proguard_files"]
    print(f"Build files scanned: {len(build_files)}")
    print(f"ProGuard files scanned: {len(proguard_files)}")
    if proguard_files:
        print("ProGuard files:")
        for path in proguard_files:
            print(f"  - {path}")
    print()
    if not findings:
        print("No obvious pre-obfuscation risks found.")
        return
    print(f"Findings: {len(findings)}")
    for index, finding in enumerate(findings, start=1):
        print(f"{index}. [{finding.severity.upper()}] {finding.category}: {finding.message}")
        for evidence in finding.evidence[:8]:
            print(f"   evidence: {evidence}")
        if len(finding.evidence) > 8:
            print(f"   evidence: ... {len(finding.evidence) - 8} more")
        if finding.recommendation:
            print(f"   fix: {finding.recommendation}")
        print()


def print_json(summary: dict[str, object], findings: list[Finding]) -> None:
    payload = {
        "summary": summary,
        "findings": [finding.as_dict() for finding in findings],
    }
    print(json.dumps(payload, indent=2, sort_keys=True))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Flag Android obfuscation issues before release builds break.")
    parser.add_argument("repo", help="Path to the Android repository to analyze.")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="Output format.")
    parser.add_argument("--include-tests", action="store_true", help="Include src/test and src/androidTest in analysis.")
    args = parser.parse_args(argv)

    repo_root = Path(args.repo).expanduser().resolve()
    if not repo_root.exists():
        print(f"Repository does not exist: {repo_root}", file=sys.stderr)
        return 2
    if not repo_root.is_dir():
        print(f"Repository path is not a directory: {repo_root}", file=sys.stderr)
        return 2

    summary, findings = analyze_repo(repo_root, include_tests=args.include_tests)
    if args.format == "json":
        print_json(summary, findings)
    else:
        print_report(summary, findings)
    return 1 if any(f.severity == "high" for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
