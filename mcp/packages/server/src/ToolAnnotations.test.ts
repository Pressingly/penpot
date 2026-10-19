import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { annotationsFor, isClassified } from "./ToolAnnotations";

const toolsDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "tools");

const TOOL_NAME_PATTERN = /getToolName\(\)\s*:\s*string\s*\{\s*return\s*["'`]([^"'`]+)["'`]/;

const CONCRETE_TOOL_PATTERN = /^export class \w+ extends Tool</m;

function readToolSource(file: string): string {
    return fs.readFileSync(path.join(toolsDir, file), "utf-8");
}

function toolSourceFiles(): string[] {
    return fs
        .readdirSync(toolsDir)
        .filter((file) => file.endsWith(".ts") && !file.endsWith(".test.ts"))
        .filter((file) => CONCRETE_TOOL_PATTERN.test(readToolSource(file)));
}

function extractToolName(file: string): string | undefined {
    return readToolSource(file).match(TOOL_NAME_PATTERN)?.[1];
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

test("names that only exist on Object.prototype fall back to a destructive write", () => {
    for (const name of ["constructor", "toString", "__proto__", "hasOwnProperty"]) {
        assert.equal(isClassified(name), false, name);
        assert.deepEqual(annotationsFor(name, false), { readOnlyHint: false, destructiveHint: true }, name);
        assert.deepEqual(annotationsFor(name, true), { readOnlyHint: false, destructiveHint: true }, name);
    }
});

test("every tool class under tools/ is classified explicitly", () => {
    const files = toolSourceFiles();
    const unreadable = files.filter((file) => extractToolName(file) === undefined);
    assert.deepEqual(unreadable, [], `could not extract getToolName() from: ${unreadable.join(", ")}`);
    assert.equal(
        files.length,
        fs.readdirSync(toolsDir).filter((f) => f.endsWith(".ts")).length,
        "a non-tool file lives in tools/"
    );
    for (const file of files) {
        const name = extractToolName(file) as string;
        assert.ok(isClassified(name), `${name} (${file}) is missing from the annotation table`);
    }
});
