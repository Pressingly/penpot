import assert from "node:assert/strict";
import test from "node:test";
import { ImportImageTool } from "./tools/ImportImageTool";

type ImportCall = unknown[];

const build = (fileName: string, mimeType = "image/png", base64Data = "QUJD") =>
    ImportImageTool.buildImportCode({ base64Data, mimeType, fileName, x: 1, y: 2, width: 3, height: 4 });

const run = async (code: string) => {
    const imports: ImportCall[] = [];
    const sentinel: string[] = [];
    const penpotUtils = {
        importImage: async (...callArgs: unknown[]) => {
            imports.push(callArgs);
            return { id: "shape-1" };
        },
    };
    const penpot = { root: { remove: () => sentinel.push("remove") } };
    const ctx = { penpotUtils, penpot };
    const fn = new Function(...Object.keys(ctx), "return (async () => { " + code + " })();");
    const result = await fn(...Object.values(ctx));
    return { result, imports, sentinel };
};

const payloads = [
    `x"); penpot.root.remove(); ("`,
    "x'); penpot.root.remove(); ('",
    "x`); penpot.root.remove(); (`",
    "${penpot.root.remove()}",
    "x\n); penpot.root.remove(); //",
    "x\r); penpot.root.remove(); //",
    `x\\'); penpot.root.remove(); ('`,
    "x penpot.root.remove();//",
];

test("passes plain values and coordinates to importImage", async () => {
    const { result, imports, sentinel } = await run(build("a.png"));
    assert.deepEqual(result, { shapeId: "shape-1" });
    assert.deepEqual(imports, [["QUJD", "image/png", "a.png", 1, 2, 3, 4]]);
    assert.deepEqual(sentinel, []);
});

test("passes undefined for omitted placement arguments", async () => {
    const code = ImportImageTool.buildImportCode({ base64Data: "QUJD", mimeType: "image/png", fileName: "a.png" });
    const { imports } = await run(code);
    assert.deepEqual(imports, [["QUJD", "image/png", "a.png", undefined, undefined, undefined, undefined]]);
});

test("embeds file name and mime type as single JSON string literals", () => {
    for (const payload of payloads) {
        assert.ok(build(payload).includes(JSON.stringify(payload)), payload);
        assert.ok(build("a.png", payload).includes(JSON.stringify(payload)), payload);
    }
});

test("treats injection-style file names as data", async () => {
    for (const payload of payloads) {
        const { imports, sentinel } = await run(build(payload));
        assert.equal(imports[0][2], payload);
        assert.deepEqual(sentinel, [], payload);
    }
});

test("treats injection-style mime types as data", async () => {
    for (const payload of payloads) {
        const { imports, sentinel } = await run(build("a.png", payload));
        assert.equal(imports[0][1], payload);
        assert.deepEqual(sentinel, [], payload);
    }
});
