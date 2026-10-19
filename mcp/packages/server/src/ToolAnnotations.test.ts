import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { annotationsFor, isClassified } from "./ToolAnnotations";

const toolsDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "tools");

function declaredToolNames(): string[] {
    return fs
        .readdirSync(toolsDir)
        .filter((file) => file.endsWith(".ts"))
        .flatMap((file) => {
            const source = fs.readFileSync(path.join(toolsDir, file), "utf-8");
            const match = source.match(/getToolName\(\): string \{\s*return "([^"]+)"/);
            return match ? [match[1]] : [];
        });
}

test("read-only tools are published as non-destructive reads", () => {
    for (const name of [
        "high_level_overview",
        "penpot_api_info",
        "export_shape",
        "cljs_compiler_output",
        "clj_check_parentheses",
        "read_taiga_issue",
    ]) {
        assert.deepEqual(annotationsFor(name, false), { readOnlyHint: true, destructiveHint: false }, name);
    }
});

test("export_shape is read-only without filesystem access", () => {
    assert.deepEqual(annotationsFor("export_shape", false), { readOnlyHint: true, destructiveHint: false });
});

test("export_shape can overwrite a local file, so it is a destructive write with filesystem access", () => {
    assert.deepEqual(annotationsFor("export_shape", true), { readOnlyHint: false, destructiveHint: true });
});

test("execute_code and cljs_repl are destructive writes", () => {
    for (const name of ["execute_code", "cljs_repl"]) {
        assert.deepEqual(annotationsFor(name, false), { readOnlyHint: false, destructiveHint: true }, name);
    }
});

test("import tools only add, so they are non-destructive writes", () => {
    for (const name of ["import_image", "import_penpot_file"]) {
        assert.deepEqual(annotationsFor(name, false), { readOnlyHint: false, destructiveHint: false }, name);
    }
});

test("an unclassified tool is a destructive write", () => {
    assert.deepEqual(annotationsFor("brand_new_tool", false), { readOnlyHint: false, destructiveHint: true });
});

test("returned annotations cannot mutate the table", () => {
    annotationsFor("execute_code", false).readOnlyHint = true;
    assert.equal(annotationsFor("execute_code", false).readOnlyHint, false);
});

test("every tool class under tools/ is classified explicitly", () => {
    const names = declaredToolNames();
    assert.ok(names.length >= 10, `expected to discover all tools, found ${names.length}`);
    for (const name of names) {
        assert.ok(isClassified(name), `${name} is missing from the annotation table`);
    }
});
