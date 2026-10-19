import type { ToolAnnotations } from "@modelcontextprotocol/sdk/types.js";

const READ_ONLY: ToolAnnotations = { readOnlyHint: true, destructiveHint: false };
const ADDITIVE_WRITE: ToolAnnotations = { readOnlyHint: false, destructiveHint: false };
const DESTRUCTIVE_WRITE: ToolAnnotations = { readOnlyHint: false, destructiveHint: true };

const ANNOTATIONS_BY_TOOL_NAME: Readonly<Record<string, ToolAnnotations>> = {
    high_level_overview: READ_ONLY,
    penpot_api_info: READ_ONLY,
    cljs_compiler_output: READ_ONLY,
    clj_check_parentheses: READ_ONLY,
    read_taiga_issue: READ_ONLY,
    import_image: ADDITIVE_WRITE,
    import_penpot_file: ADDITIVE_WRITE,
    execute_code: DESTRUCTIVE_WRITE,
    cljs_repl: DESTRUCTIVE_WRITE,
};

function resolveAnnotations(toolName: string, fileSystemAccess: boolean): ToolAnnotations | undefined {
    if (toolName === "export_shape") {
        return fileSystemAccess ? DESTRUCTIVE_WRITE : READ_ONLY;
    }
    return ANNOTATIONS_BY_TOOL_NAME[toolName];
}

export function isClassified(toolName: string): boolean {
    return toolName === "export_shape" || toolName in ANNOTATIONS_BY_TOOL_NAME;
}

/**
 * Returns the MCP behaviour annotations published for the given tool.
 *
 * A tool missing from the table is published as a destructive write, so a newly added tool can never
 * be advertised as read-only by accident.
 *
 * `export_shape` can write (and overwrite) a local file when filesystem access is enabled, so it is a
 * destructive write in that mode and read-only otherwise.
 */
export function annotationsFor(toolName: string, fileSystemAccess: boolean): ToolAnnotations {
    return { ...(resolveAnnotations(toolName, fileSystemAccess) ?? DESTRUCTIVE_WRITE) };
}
