import assert from "node:assert/strict";
import test from "node:test";
import { ExportShapeTool } from "./tools/ExportShapeTool";

const build = (shapeId: string) => ExportShapeTool.buildExportCode({ shapeId, format: "png", mode: "shape" });

test("embeds a plain shape id as a string literal", () => {
    assert.equal(
        build("abc-123"),
        `return penpotUtils.exportImage(penpotUtils.findShapeById("abc-123"), "shape", false);`
    );
});

test("keeps the special selection and page identifiers", () => {
    assert.match(build("selection"), /exportImage\(penpot\.selection\[0\],/);
    assert.match(build("page"), /exportImage\(penpot\.root,/);
});

test("treats injection-style shape ids as a single string literal", () => {
    const payloads = [
        `x"); penpot.root.remove(); ("`,
        "x`); penpot.root.remove(); (`",
        "${penpot.root.remove()}",
        `x"\n); penpot.root.remove(); //`,
        `x\\"); penpot.root.remove(); ("`,
        "x ); penpot.root.remove(); //",
    ];
    for (const payload of payloads) {
        const code = build(payload);
        const prefix = "return penpotUtils.exportImage(penpotUtils.findShapeById(";
        const suffix = `), "shape", false);`;
        assert.ok(code.startsWith(prefix) && code.endsWith(suffix), payload);
        const literal = code.slice(prefix.length, code.length - suffix.length);
        assert.equal(JSON.parse(literal), payload);
        const calls: string[] = [];
        const penpotUtils = {
            findShapeById: (id: string) => id,
            exportImage: (shape: string) => shape,
        };
        const penpot = { root: { remove: () => calls.push("remove") } };
        const result = new Function("penpotUtils", "penpot", code)(penpotUtils, penpot);
        assert.equal(result, payload);
        assert.deepEqual(calls, []);
    }
});
