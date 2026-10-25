let electron = require("electron");
let node_fs = require("node:fs");
let node_fs_promises = require("node:fs/promises");
let node_path = require("node:path");
let node_crypto = require("node:crypto");
let node_child_process = require("node:child_process");
let node_os = require("node:os");
let node_string_decoder = require("node:string_decoder");
let node_http = require("node:http");
let node_https = require("node:https");
let node_stream_promises = require("node:stream/promises");
//#region src/main/pathGuard.ts
/**
* 路径越界校验。
*
* 这是整个文件访问的唯一安全边界，所以刻意抽成**不依赖 electron 的纯模块** ——
* 安全关键代码必须能被独立测试，而不是埋在需要 mock Electron 的文件里。
*
* 最容易写错的地方：不能用 `target.startsWith(root)` 判断。
* 假设 root 是 `C:\work\demo`，那么 `C:\work\demo-evil\x.txt` 也会满足前缀匹配，
* 于是越界成功。必须比较 `root + sep`。
*/
function resolveInside(root, relativePath) {
	const target = (0, node_path.resolve)(root, relativePath);
	if (target === root) return target;
	if (!target.startsWith(root + node_path.sep)) throw new Error(`拒绝访问工作区之外的路径：${relativePath}`);
	return target;
}
//#endregion
//#region src/main/plugins/bootstrap.ts
/**
* 插件沙箱的引导页与引导脚本。
*
* 它们是**主进程生成的字符串**，由 app:// 协议在插件自己的 origin 下提供。
* 为什么要这样：插件的代码必须跑在插件自己的 origin（独立存储、独立 CSP），
* 而引导逻辑又是我们自己的代码 —— 于是让协议按固定路径把它发出去，
* 既不用为每个插件生成构建产物，也不需要在 HTML 里写内联脚本
* （内联脚本会迫使 CSP 放开 'unsafe-inline'，得不偿失）。
*/
/** 引导页路径。请求它时协议返回 pluginHostHtml() */
var PLUGIN_HOST_PATH = "/__sparkle_host__.html";
/** 引导脚本路径。请求它时协议返回 PLUGIN_BOOTSTRAP_JS */
var PLUGIN_BOOTSTRAP_PATH = "/__sparkle_bootstrap__.js";
function pluginHostHtml() {
	return `<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="UTF-8" />
    <title>Sparkle 插件沙箱</title>
  </head>
  <body>
    <script type="module" src="${PLUGIN_BOOTSTRAP_PATH}"><\/script>
  </body>
</html>
`;
}
/**
* 引导脚本：读出入口 → import → 调用插件的 activate(api) → 报告就绪。
*
* 任何异常都必须报告给主进程，而不是烂在沙箱里 ——
* 否则用户只会看到"插件没反应"，完全无从排查。
*/
var PLUGIN_BOOTSTRAP_JS = `const params = new URLSearchParams(location.search)
const entry = params.get('main') || 'index.js'

try {
  const module = await import(new URL(entry, location.href).href)
  const candidate =
    module.activate ??
    (module.default && (module.default.activate ?? module.default)) ??
    null

  if (typeof candidate === 'function') {
    await candidate(window.sparklePlugin)
  }

  window.sparklePlugin.notifyReady()
} catch (error) {
  window.sparklePlugin.reportFatal(String((error && error.stack) || error))
}
`;
/**
* 插件 origin 的 CSP。
*
* connect-src 'none' 是关键：插件的 fetch / XHR / WebSocket / EventSource
* 会被浏览器直接拒绝。**即使授予了 network 权限，插件也无法自行联网**，
* 只能通过主进程代理 —— 于是主进程能审计、能限流、能撤回。
*
* default-src 'none' 起步，再逐项放开必需的能力。
*/
var PLUGIN_CSP = [
	"default-src 'none'",
	"script-src 'self'",
	"style-src 'self' 'unsafe-inline'",
	"img-src 'self' data:",
	"font-src 'self' data:",
	"connect-src 'none'",
	"form-action 'none'",
	"base-uri 'none'",
	"frame-src 'none'",
	"object-src 'none'"
].join("; ");
var APP_ORIGIN = `app://bundle`;
var MIME_TYPES = {
	".html": "text/html; charset=utf-8",
	".js": "text/javascript; charset=utf-8",
	".mjs": "text/javascript; charset=utf-8",
	".css": "text/css; charset=utf-8",
	".json": "application/json; charset=utf-8",
	".map": "application/json; charset=utf-8",
	".svg": "image/svg+xml",
	".png": "image/png",
	".jpg": "image/jpeg",
	".webp": "image/webp",
	".ico": "image/x-icon",
	".woff": "font/woff",
	".woff2": "font/woff2",
	".ttf": "font/ttf"
};
/**
* 必须在 app ready 之前调用。
* standard: true 让它拥有正常的 origin 语义（Worker、fetch、CSP 都依赖它）。
*/
function registerAppSchemePrivileges() {
	electron.protocol.registerSchemesAsPrivileged([{
		scheme: "app",
		privileges: {
			standard: true,
			secure: true,
			supportFetchAPI: true,
			corsEnabled: true,
			stream: true
		}
	}]);
}
function contentTypeFor(filePath) {
	return MIME_TYPES[(0, node_path.extname)(filePath).toLowerCase()] ?? "application/octet-stream";
}
function notFound() {
	return new Response("Not Found", { status: 404 });
}
/**
* URL 路径 → 相对路径。**必须去掉开头的斜杠。**
*
* 这不是理论风险，是真实踩过的坑：
*   浏览器给的 pathname 是 `/index.js`，
*   而 `path.resolve(root, '/index.js')` 在 Windows 上会得到 `C:\index.js` ——
*   变成一个绝对路径，于是被路径守卫正确地判成"越界"，
*   插件入口永远 404，表现为"沙箱加载成功但插件毫无反应"。
*   （渲染层那边没踩到，只是因为那里用的是 join，join 不会因前导斜杠重置到根。）
*/
function urlPathToRelative(pathname) {
	return pathname.replace(/^[/\\]+/, "");
}
/** 构造 app:// 的请求处理器。同一个处理器可以挂到多个 session 上。 */
function buildHandler(options) {
	const rendererRoot = (0, node_path.normalize)(options.rendererDir);
	const report = options.onRequest ?? (() => {});
	return async (request) => {
		let url;
		try {
			url = new URL(request.url);
		} catch {
			return new Response("Bad Request", { status: 400 });
		}
		const host = url.hostname;
		const pathname = decodeURIComponent(url.pathname);
		if (host.startsWith("plugin-")) {
			const pluginId = host.slice(7);
			const directory = options.resolvePluginDir(pluginId);
			if (!directory) {
				report({
					host,
					pathname,
					outcome: "未知插件 → 404"
				});
				return notFound();
			}
			if (pathname === "/__sparkle_host__.html") {
				report({
					host,
					pathname,
					outcome: "引导页 200"
				});
				return new Response(pluginHostHtml(), { headers: {
					"content-type": "text/html; charset=utf-8",
					"content-security-policy": PLUGIN_CSP,
					"cache-control": "no-store"
				} });
			}
			if (pathname === "/__sparkle_bootstrap__.js") {
				report({
					host,
					pathname,
					outcome: "引导脚本 200"
				});
				return new Response(PLUGIN_BOOTSTRAP_JS, { headers: {
					"content-type": "text/javascript; charset=utf-8",
					"content-security-policy": PLUGIN_CSP,
					"cache-control": "no-store"
				} });
			}
			try {
				const filePath = resolveInside((0, node_path.normalize)(directory), urlPathToRelative(pathname));
				const data = await (0, node_fs_promises.readFile)(filePath);
				report({
					host,
					pathname,
					outcome: "插件文件 200"
				});
				return new Response(new Uint8Array(data), { headers: {
					"content-type": contentTypeFor(filePath),
					"content-security-policy": PLUGIN_CSP,
					"cache-control": "no-store"
				} });
			} catch (error) {
				report({
					host,
					pathname,
					outcome: `插件文件失败：${error instanceof Error ? error.message : String(error)}`
				});
				return notFound();
			}
		}
		let relativePath = urlPathToRelative(pathname);
		if (relativePath === "" || relativePath.endsWith("/")) relativePath += "index.html";
		const filePath = (0, node_path.normalize)((0, node_path.join)(rendererRoot, relativePath));
		if (filePath !== rendererRoot && !filePath.startsWith(rendererRoot + node_path.sep)) return new Response("Forbidden", { status: 403 });
		try {
			const data = await (0, node_fs_promises.readFile)(filePath);
			return new Response(new Uint8Array(data), { headers: {
				"content-type": contentTypeFor(filePath),
				"cache-control": "no-cache"
			} });
		} catch {
			return notFound();
		}
	};
}
/** 给默认 session 注册（IDE 主界面走这条） */
function serveCustomProtocols(options) {
	electron.session.defaultSession.protocol.handle("app", buildHandler(options));
}
/**
* 给指定 partition 的 session 注册。
*
* **这是必需的一步，不是可选项。** `protocol.handle` 是按 session 注册的，
* 而插件沙箱用了独立 partition（为了存储隔离），那个 session 上默认
* 没有任何 app:// 处理器。结果是沙箱页面静默加载失败 ——
* 连 did-fail-load 都不触发，只表现为"激活超时"，极难排查。
*/
function serveCustomProtocolsForPartition(partition, options) {
	const target = electron.session.fromPartition(partition);
	if (target.protocol.isProtocolHandled("app")) return;
	target.protocol.handle("app", buildHandler(options));
}
//#endregion
//#region src/shared/plugin.ts
var PLUGIN_PERMISSIONS = [
	"workspace:read",
	"workspace:write",
	"network",
	"process"
];
var PLUGIN_ID_PATTERN = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/;
var VERSION_PATTERN = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;
var ENTRY_PATTERN = /\.(?:js|mjs)$/;
var MAX_NAME_LENGTH = 60;
var MAX_DESCRIPTION_LENGTH = 400;
/** 入口必须是插件目录内的相对路径，且只能是 JS。这是插件的"路径越界"防线。 */
function checkEntryPath(entry) {
	if (typeof entry !== "string" || entry.trim() === "") return "main 必须是非空的相对路径";
	const value = entry.trim();
	if (value.startsWith("/") || value.startsWith("\\")) return "main 不能是绝对路径";
	if (/^[A-Za-z]:/.test(value)) return "main 不能包含盘符";
	if (value.split(/[\\/]/).includes("..")) return "main 不能包含 ..，必须位于插件目录内";
	if (!ENTRY_PATTERN.test(value)) return "main 必须是 .js 或 .mjs 文件";
	return null;
}
function isValidPluginId(id) {
	return typeof id === "string" && id.length <= 80 && PLUGIN_ID_PATTERN.test(id);
}
/**
* 校验清单。清单是**来自磁盘的不可信输入**（将来还来自市场），
* 所以这里逐字段严格检查，并一次性返回所有问题而不是遇到第一个就退出 ——
* 插件作者一次就能看到全部要改的地方。
*/
function validatePluginManifest(raw) {
	const errors = [];
	const unknownPermissions = [];
	if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return {
		ok: false,
		manifest: null,
		errors: ["清单必须是一个 JSON 对象"],
		unknownPermissions
	};
	const input = raw;
	if (!isValidPluginId(input.id)) errors.push("id 非法：需为小写点分标识，例如 sparkle.python-helper");
	const name = typeof input.name === "string" ? input.name.trim() : "";
	if (!name) errors.push("name 不能为空");
	else if (name.length > MAX_NAME_LENGTH) errors.push(`name 不能超过 ${MAX_NAME_LENGTH} 个字符`);
	if (typeof input.version !== "string" || !VERSION_PATTERN.test(input.version.trim())) errors.push("version 非法：需形如 1.0.0");
	const entryError = checkEntryPath(input.main);
	if (entryError) errors.push(entryError);
	let description;
	if (input.description !== void 0) {
		if (typeof input.description !== "string") errors.push("description 必须是字符串");
		else if (input.description.length > MAX_DESCRIPTION_LENGTH) errors.push(`description 不能超过 ${MAX_DESCRIPTION_LENGTH} 个字符`);
		else description = input.description;
	}
	const permissions = [];
	if (input.permissions !== void 0) {
		if (!Array.isArray(input.permissions)) errors.push("permissions 必须是数组");
		else for (const item of input.permissions) {
			if (typeof item !== "string") {
				errors.push("permissions 里的每一项都必须是字符串");
				continue;
			}
			if (PLUGIN_PERMISSIONS.includes(item)) {
				if (!permissions.includes(item)) permissions.push(item);
			} else unknownPermissions.push(item);
		}
	}
	const activation = [];
	if (input.activation !== void 0) {
		if (!Array.isArray(input.activation)) errors.push("activation 必须是数组");
		else for (const item of input.activation) {
			if (typeof item !== "string" || item.trim() === "") {
				errors.push("activation 的每一项都必须是非空字符串");
				continue;
			}
			activation.push(item.trim());
		}
	}
	const commands = [];
	const contributes = input.contributes;
	if (contributes !== void 0) {
		if (typeof contributes !== "object" || contributes === null || Array.isArray(contributes)) errors.push("contributes 必须是对象");
		else {
			const rawCommands = contributes.commands;
			if (rawCommands !== void 0) {
				if (!Array.isArray(rawCommands)) errors.push("contributes.commands 必须是数组");
				else for (const item of rawCommands) {
					if (typeof item !== "object" || item === null) {
						errors.push("contributes.commands 的每一项都必须是对象");
						continue;
					}
					const command = item;
					const id = typeof command.id === "string" ? command.id.trim() : "";
					const title = typeof command.title === "string" ? command.title.trim() : "";
					if (!id) errors.push("命令缺少 id");
					if (!title) errors.push(`命令 ${id || "(无 id)"} 缺少 title`);
					if (id && title) commands.push({
						id,
						title
					});
				}
			}
		}
	}
	if (errors.length > 0) return {
		ok: false,
		manifest: null,
		errors,
		unknownPermissions
	};
	return {
		ok: true,
		errors: [],
		unknownPermissions,
		manifest: {
			id: input.id.trim(),
			name,
			version: input.version.trim(),
			description,
			main: input.main.trim(),
			activation,
			permissions,
			contributes: { commands }
		}
	};
}
var COMPLETION_KINDS = [
	"text",
	"method",
	"function",
	"variable",
	"class",
	"keyword",
	"snippet"
];
var MAX_LABEL_LENGTH = 200;
var MAX_TEXT_LENGTH = 2e3;
/**
* 把插件返回的补全列表洗成可信数据。
*
* 插件返回值是**跨越隔离边界的不可信输入**：可能是一个有十万条目的数组、
* 可能是奇怪的类型、可能带超长字符串。直接交给 Monaco 会卡死界面，
* 所以这里逐字段校验 + 截断 + 限数量。
*/
function sanitizeCompletionItems(value) {
	if (typeof value !== "object" || value === null) return [];
	const rawItems = value.items;
	if (!Array.isArray(rawItems)) return [];
	const result = [];
	for (const raw of rawItems) {
		if (result.length >= 200) break;
		if (typeof raw !== "object" || raw === null) continue;
		const item = raw;
		const label = typeof item.label === "string" ? item.label.slice(0, MAX_LABEL_LENGTH) : "";
		if (!label) continue;
		const kind = typeof item.kind === "string" && COMPLETION_KINDS.includes(item.kind) ? item.kind : "text";
		result.push({
			label,
			kind,
			insertText: typeof item.insertText === "string" ? item.insertText.slice(0, MAX_TEXT_LENGTH) : void 0,
			detail: typeof item.detail === "string" ? item.detail.slice(0, MAX_LABEL_LENGTH) : void 0,
			documentation: typeof item.documentation === "string" ? item.documentation.slice(0, MAX_TEXT_LENGTH) : void 0
		});
	}
	return result;
}
var PLUGIN_CHANNELS = {
	list: "plugin:list",
	openFolder: "plugin:openFolder",
	setGranted: "plugin:setGranted",
	activate: "plugin:activate",
	deactivate: "plugin:deactivate",
	provideCompletions: "plugin:provideCompletions",
	cancel: "plugin:cancel",
	listSolvers: "plugin:listSolvers",
	runSolver: "plugin:runSolver",
	sandboxActivate: "plugin-sandbox:activate",
	sandboxRpc: "plugin-sandbox:rpc",
	sandboxCancel: "plugin-sandbox:cancel",
	sandboxReady: "plugin-sandbox:ready",
	sandboxReply: "plugin-sandbox:reply",
	sandboxRegistered: "plugin-sandbox:registered",
	sandboxRequest: "plugin-sandbox:request",
	sandboxFatal: "plugin-sandbox:fatal",
	sandboxLog: "plugin-sandbox:log",
	changed: "plugin:changed"
};
/** 插件返回的数据一律当不可信处理：限长、限数量、限深度 */
var MAX_VIEW_ITEMS = 400;
var MAX_VIEW_TEXT = 2e4;
var MAX_STEPS = 200;
var MAX_TREE_DEPTH = 6;
function sanitizeText(value, limit = 400) {
	if (typeof value !== "string") return "";
	return value.length > limit ? `${value.slice(0, limit)}…` : value;
}
function sanitizeCell(value) {
	if (typeof value === "number" && Number.isFinite(value)) return value;
	if (typeof value === "string") return sanitizeText(value, 40);
	if (typeof value === "boolean") return value ? "是" : "否";
	return "";
}
function sanitizeTreeNode(items, depth) {
	if (!Array.isArray(items) || depth > MAX_TREE_DEPTH) return [];
	return items.slice(0, MAX_VIEW_ITEMS).map((item) => {
		const node = item ?? {};
		return {
			id: sanitizeText(node.id, 60),
			label: sanitizeText(node.label, 40),
			note: sanitizeText(node.note, 40) || void 0,
			highlight: node.highlight === true,
			children: sanitizeTreeNode(node.children, depth + 1)
		};
	});
}
/** 把插件返回的可视化描述清洗成宿主可以安全渲染的结构 */
function sanitizeView(input) {
	if (!input || typeof input !== "object") return void 0;
	const raw = input;
	const title = sanitizeText(raw.title, 120);
	switch (raw.kind) {
		case "array": return {
			kind: "array",
			title,
			values: (Array.isArray(raw.values) ? raw.values.slice(0, MAX_VIEW_ITEMS) : []).map(sanitizeCell),
			highlights: Array.isArray(raw.highlights) ? raw.highlights.filter((item) => typeof item === "number").slice(0, 200) : void 0,
			labels: Array.isArray(raw.labels) ? raw.labels.slice(0, MAX_VIEW_ITEMS).map((item) => sanitizeText(item, 20)) : void 0
		};
		case "tree": return {
			kind: "tree",
			title,
			nodes: sanitizeTreeNode(raw.nodes, 0)
		};
		case "graph": return {
			kind: "graph",
			title,
			directed: raw.directed === true,
			nodes: (Array.isArray(raw.nodes) ? raw.nodes.slice(0, MAX_VIEW_ITEMS) : []).map((item) => {
				const node = item ?? {};
				return {
					id: sanitizeText(node.id, 60),
					label: sanitizeText(node.label, 40) || void 0,
					group: sanitizeText(node.group, 40) || void 0,
					highlight: node.highlight === true
				};
			}),
			edges: (Array.isArray(raw.edges) ? raw.edges.slice(0, MAX_VIEW_ITEMS * 2) : []).map((item) => {
				const edge = item ?? {};
				return {
					from: sanitizeText(edge.from, 60),
					to: sanitizeText(edge.to, 60),
					label: sanitizeText(edge.label, 20) || void 0,
					highlight: edge.highlight === true
				};
			})
		};
		case "matrix": return {
			kind: "matrix",
			title,
			columns: Array.isArray(raw.columns) ? raw.columns.slice(0, 64).map((item) => sanitizeText(item, 20)) : void 0,
			rows: (Array.isArray(raw.rows) ? raw.rows.slice(0, MAX_VIEW_ITEMS) : []).map((item) => {
				const row = item ?? {};
				return {
					header: sanitizeText(row.header, 40) || void 0,
					cells: Array.isArray(row.cells) ? row.cells.slice(0, 64).map(sanitizeCell) : [],
					highlight: Array.isArray(row.highlight) ? row.highlight.filter((cell) => typeof cell === "number") : void 0
				};
			})
		};
		case "steps": return {
			kind: "steps",
			title,
			steps: (Array.isArray(raw.steps) ? raw.steps.slice(0, MAX_STEPS) : []).map((item) => {
				const step = item ?? {};
				return {
					title: sanitizeText(step.title, 160),
					detail: sanitizeText(step.detail, 300)
				};
			})
		};
		case "text": return {
			kind: "text",
			title,
			text: sanitizeText(raw.text, MAX_VIEW_TEXT)
		};
		default: return;
	}
}
/** 清洗求解结果 */
function sanitizeSolverResult(input) {
	const raw = input ?? {};
	return {
		text: sanitizeText(raw.text, MAX_VIEW_TEXT) || "（插件没有给出结论）",
		view: sanitizeView(raw.view),
		note: sanitizeText(raw.note, 600) || void 0
	};
}
//#endregion
//#region src/shared/fs.ts
/** 单文件读取上限：超过就只读开头并标记，避免一个巨大文件把内存吃掉 */
var MAX_FILE_BYTES = 20971520;
var FS_CHANNELS = {
	openFolder: "fs:openFolder",
	currentWorkspace: "fs:currentWorkspace",
	readDirectory: "fs:readDirectory",
	readFile: "fs:readFile",
	saveFile: "fs:saveFile",
	createFile: "fs:createFile",
	createDirectory: "fs:createDirectory",
	renameEntry: "fs:renameEntry",
	deleteEntry: "fs:deleteEntry"
};
//#endregion
//#region src/main/fileService.ts
/**
* 纯文件操作。
*
* 刻意**不 import electron** —— 这样整层都能在 vitest 里用真实临时文件测试。
* 文件读写是核心功能，不该因为"它所在的模块要弹对话框"而变得不可测。
*
* 所有函数都显式接收 root，不依赖模块级状态：一来可测，
* 二来杜绝了"忘了设工作区就误操作到别处"这类问题。
*/
/** 这些目录不展开。node_modules 动辄几万个文件，读进来只会让 IDE 卡死。 */
var IGNORED_DIRECTORIES = /* @__PURE__ */ new Set([
	"node_modules",
	".git",
	".hg",
	".svn",
	"out",
	"dist",
	"build",
	"release",
	".next",
	".nuxt",
	".svelte-kit",
	".cache",
	".parcel-cache",
	"__pycache__",
	".venv",
	"venv",
	"target",
	"coverage",
	".pytest_cache",
	".mypy_cache",
	".ruff_cache",
	".idea"
]);
async function readDirectory$1(root, relativePath) {
	const target = resolveInside(root, relativePath);
	const dirents = await (0, node_fs_promises.readdir)(target, { withFileTypes: true });
	const entries = [];
	let truncated = false;
	for (const dirent of dirents) {
		const isDirectory = dirent.isDirectory();
		if (isDirectory && IGNORED_DIRECTORIES.has(dirent.name)) continue;
		if (dirent.isSymbolicLink()) continue;
		if (entries.length >= 5e3) {
			truncated = true;
			break;
		}
		entries.push({
			name: dirent.name,
			path: relativePath ? `${relativePath}/${dirent.name}` : dirent.name,
			kind: isDirectory ? "directory" : "file"
		});
	}
	entries.sort((a, b) => {
		if (a.kind !== b.kind) return a.kind === "directory" ? -1 : 1;
		return a.name.localeCompare(b.name, "zh-Hans-CN");
	});
	return {
		path: relativePath,
		entries,
		truncated
	};
}
async function readFileContent$1(root, relativePath) {
	const target = resolveInside(root, relativePath);
	const info = await (0, node_fs_promises.stat)(target);
	const toRead = Math.min(info.size, MAX_FILE_BYTES);
	const buffer = Buffer.alloc(toRead);
	const handle = await (0, node_fs_promises.open)(target, "r");
	try {
		if (toRead > 0) await handle.read(buffer, 0, toRead, 0);
	} finally {
		await handle.close();
	}
	const probeLength = Math.min(buffer.length, 8e3);
	let binary = false;
	for (let index = 0; index < probeLength; index += 1) if (buffer[index] === 0) {
		binary = true;
		break;
	}
	return {
		path: relativePath,
		content: binary ? "" : buffer.toString("utf8"),
		bytes: info.size,
		truncated: info.size > MAX_FILE_BYTES,
		binary
	};
}
async function saveFile$1(root, relativePath, content) {
	const target = resolveInside(root, relativePath);
	await (0, node_fs_promises.writeFile)(target, content, "utf8");
	return {
		path: relativePath,
		bytes: Buffer.byteLength(content, "utf8"),
		savedAt: Date.now()
	};
}
//#endregion
//#region src/main/plugins/registry.ts
async function discoverPlugins(roots) {
	const records = [];
	const broken = [];
	const seenIds = /* @__PURE__ */ new Set();
	for (const root of roots) {
		let entries;
		try {
			entries = (await (0, node_fs_promises.readdir)(root, { withFileTypes: true })).filter((dirent) => dirent.isDirectory()).map((dirent) => dirent.name);
		} catch {
			continue;
		}
		for (const name of entries) {
			const directory = (0, node_path.resolve)((0, node_path.join)(root, name));
			const manifestPath = (0, node_path.join)(directory, "sparkle.json");
			let rawText;
			try {
				if (!(await (0, node_fs_promises.stat)(manifestPath)).isFile()) {
					broken.push({
						directory,
						reason: "sparkle.json 不是文件"
					});
					continue;
				}
				rawText = await (0, node_fs_promises.readFile)(manifestPath, "utf8");
			} catch {
				broken.push({
					directory,
					reason: "缺少 sparkle.json"
				});
				continue;
			}
			let parsed;
			try {
				parsed = JSON.parse(rawText);
			} catch (error) {
				broken.push({
					directory,
					reason: `sparkle.json 不是合法 JSON：${error instanceof Error ? error.message : String(error)}`
				});
				continue;
			}
			const result = validatePluginManifest(parsed);
			if (!result.ok || !result.manifest) {
				broken.push({
					directory,
					reason: result.errors.join("；")
				});
				continue;
			}
			if (seenIds.has(result.manifest.id)) {
				broken.push({
					directory,
					reason: `插件 id 重复：${result.manifest.id}`
				});
				continue;
			}
			seenIds.add(result.manifest.id);
			records.push({
				manifest: result.manifest,
				directory,
				granted: [],
				state: "inactive",
				sandboxAlive: false,
				lastActiveAt: 0,
				solvers: /* @__PURE__ */ new Map()
			});
		}
	}
	records.sort((a, b) => a.manifest.name.localeCompare(b.manifest.name, "zh-Hans-CN"));
	return {
		records,
		broken
	};
}
/** 下发给渲染层时必须剔除绝对路径 */
function summarize(record) {
	return {
		id: record.manifest.id,
		name: record.manifest.name,
		version: record.manifest.version,
		description: record.manifest.description,
		requested: record.manifest.permissions ?? [],
		granted: record.granted,
		activation: record.manifest.activation ?? [],
		commands: record.manifest.contributes?.commands ?? [],
		state: record.state,
		error: record.error,
		sandboxAlive: record.sandboxAlive
	};
}
/**
* 计算授权结果。
* 关键约束：**只能授权清单里声明过的权限** —— 否则插件可以在运行时
* 临时索要一个它当初没声明的能力，那用户看清单就没有意义了。
*/
function intersectGranted(manifest, requested) {
	const declared = new Set(manifest.permissions ?? []);
	if (!Array.isArray(requested)) return [];
	const result = [];
	for (const item of requested) if (typeof item === "string" && declared.has(item)) {
		const permission = item;
		if (!result.includes(permission)) result.push(permission);
	}
	return result;
}
/** 激活事件匹配。`onLanguage:python` 这类带参数的事件按前缀比较。 */
function shouldActivate(manifest, event) {
	const events = manifest.activation ?? [];
	if (events.includes("*")) return true;
	if (events.includes(event)) return true;
	const [namespace] = event.split(":");
	return namespace !== void 0 && events.includes(`${namespace}:*`);
}
//#endregion
//#region src/main/plugins/sandbox.ts
/**
* 一个插件的沙箱。
*
* 它是真正的隔离边界：独立 BrowserWindow + sandbox:true + 独立 origin +
* 独立内存会话。插件拿不到 Node，也拿不到主窗口的任何东西。
*
* 这个类刻意**不注册任何 ipcMain 监听** —— 监听统一由 host 注册一次，
* 再按 event.sender.id 路由过来。这样每装一个插件就多一组监听器的问题不存在，
* 也让"这条消息到底是不是这个插件发的"这个校验只有一个地方要做。
*/
var SANDBOX_START_TIMEOUT_MS = 8e3;
/**
* 插件的 session 名。
* 不带 persist: 前缀 = 内存会话，插件之间互不共享存储，退出即清空。
*/
function partitionForPlugin(pluginId) {
	return `sparkle-plugin-${pluginId}`;
}
var PluginSandbox = class {
	pluginId;
	entry;
	preloadPath;
	partition;
	callbacks;
	window = null;
	pending = /* @__PURE__ */ new Map();
	readyPromise = null;
	readyResolve = null;
	readyReject = null;
	startTimer = null;
	settled = false;
	/** 该插件为哪些语言注册了补全 */
	completionLanguages = /* @__PURE__ */ new Set();
	/** 该插件注册了哪些求解器（OI-Helper 这类算法插件用） */
	solverIds = /* @__PURE__ */ new Set();
	constructor(pluginId, entry, preloadPath, partition, callbacks) {
		this.pluginId = pluginId;
		this.entry = entry;
		this.preloadPath = preloadPath;
		this.partition = partition;
		this.callbacks = callbacks;
	}
	get alive() {
		return this.window !== null && !this.window.isDestroyed();
	}
	get webContentsId() {
		if (!this.window || this.window.isDestroyed()) return null;
		return this.window.webContents.id;
	}
	get pendingCount() {
		return this.pending.size;
	}
	start() {
		if (this.readyPromise) return this.readyPromise;
		this.readyPromise = new Promise((resolve, reject) => {
			this.readyResolve = resolve;
			this.readyReject = reject;
			const window = new electron.BrowserWindow({
				show: false,
				width: 480,
				height: 320,
				webPreferences: {
					preload: this.preloadPath,
					sandbox: true,
					contextIsolation: true,
					nodeIntegration: false,
					webviewTag: false,
					spellcheck: false,
					partition: this.partition,
					backgroundThrottling: false
				}
			});
			this.window = window;
			this.callbacks.onDebug?.(`窗口已创建 partition=${this.partition}`);
			window.webContents.on("did-start-loading", () => this.callbacks.onDebug?.("did-start-loading"));
			window.webContents.on("dom-ready", () => this.callbacks.onDebug?.("dom-ready"));
			window.webContents.on("did-finish-load", () => this.callbacks.onDebug?.("did-finish-load"));
			this.startTimer = setTimeout(() => {
				this.fail(/* @__PURE__ */ new Error("沙箱启动超时（插件可能在顶层代码里陷入了死循环）"));
			}, SANDBOX_START_TIMEOUT_MS);
			window.webContents.on("render-process-gone", (_event, details) => {
				this.callbacks.onGone(`沙箱进程退出：${details.reason}`);
				this.fail(/* @__PURE__ */ new Error(`沙箱进程异常退出：${details.reason}`));
			});
			window.webContents.on("did-fail-load", (_event, errorCode, errorDescription, validatedURL) => {
				this.callbacks.onDebug?.(`did-fail-load ${errorCode} ${errorDescription} ${validatedURL}`);
				this.fail(/* @__PURE__ */ new Error(`沙箱页面加载失败：${errorDescription}（${errorCode}）${validatedURL}`));
			});
			window.webContents.on("console-message", (...args) => {
				const details = args[0];
				const message = typeof details?.message === "string" ? details.message : String(args[2] ?? "");
				if (message) this.callbacks.onLog(`[沙箱控制台] ${String(message).slice(0, 400)}`);
			});
			const url = `app://plugin-${this.pluginId}${PLUGIN_HOST_PATH}?main=${encodeURIComponent(this.entry)}`;
			this.callbacks.onDebug?.(`loadURL ${url}`);
			window.loadURL(url);
		});
		return this.readyPromise;
	}
	markReady() {
		if (this.settled) return;
		this.settled = true;
		if (this.startTimer) clearTimeout(this.startTimer);
		this.startTimer = null;
		this.callbacks.onReady();
		this.readyResolve?.();
	}
	fail(error) {
		if (this.startTimer) clearTimeout(this.startTimer);
		this.startTimer = null;
		if (!this.settled) {
			this.settled = true;
			this.readyReject?.(error);
		}
		for (const [requestId, entry] of this.pending) {
			clearTimeout(entry.timer);
			entry.reject(error);
			this.pending.delete(requestId);
		}
	}
	/**
	* 向沙箱发一次 RPC。
	* 返回 requestId 是为了让调用方（host）能把它登记进"可取消"表 ——
	* 渲染层传来的取消要能一路透传到插件手里。
	*/
	request(method, params, timeoutMs) {
		const window = this.window;
		const requestId = (0, node_crypto.randomUUID)();
		if (!window || window.isDestroyed()) return {
			requestId,
			result: Promise.reject(/* @__PURE__ */ new Error("插件沙箱未运行"))
		};
		return {
			requestId,
			result: new Promise((resolve, reject) => {
				const timer = setTimeout(() => {
					this.pending.delete(requestId);
					this.sendCancel(requestId);
					reject(/* @__PURE__ */ new Error(`插件 ${this.pluginId} 响应超时（${timeoutMs} ms）`));
				}, timeoutMs);
				this.pending.set(requestId, {
					resolve,
					reject,
					timer,
					cancelled: false
				});
				window.webContents.send(PLUGIN_CHANNELS.sandboxRpc, {
					requestId,
					method,
					params
				});
			})
		};
	}
	/** 处理沙箱回传的结果。迟到的回复（已超时/已取消）直接丢弃。 */
	handleReply(reply) {
		const entry = this.pending.get(reply.requestId);
		if (!entry) return;
		this.pending.delete(reply.requestId);
		clearTimeout(entry.timer);
		if (reply.ok) entry.resolve(reply.result);
		else entry.reject(new Error(reply.error ?? "插件返回失败"));
	}
	/** 通知沙箱某个请求已取消（把取消令牌真正传到插件手里） */
	cancel(requestId) {
		const entry = this.pending.get(requestId);
		if (entry) entry.cancelled = true;
		this.sendCancel(requestId);
	}
	sendCancel(requestId) {
		const window = this.window;
		if (!window || window.isDestroyed()) return;
		window.webContents.send(PLUGIN_CHANNELS.sandboxCancel, { requestId });
	}
	handleRegistered(kind, value) {
		if (kind === "completions") this.completionLanguages.add(value);
		if (kind === "solver") try {
			const parsed = JSON.parse(value);
			if (typeof parsed.id === "string" && parsed.id) this.solverIds.add(parsed.id);
		} catch {}
		this.callbacks.onRegistered(kind, value);
	}
	destroy() {
		this.fail(/* @__PURE__ */ new Error("插件沙箱已关闭"));
		const window = this.window;
		this.window = null;
		if (window && !window.isDestroyed()) window.destroy();
	}
};
//#endregion
//#region src/main/plugins/host.ts
/**
* 插件宿主。
*
* 它是**唯一的能力持有者**：插件想要文件、网络、进程，都必须经过这里，
* 而这里会先检查"这个插件被授权了吗"、"这个请求真的来自那个插件吗"。
*
* 生命周期要点：
*   - 插件不随应用启动。只有激活事件（onCommand / onLanguage）才会拉起沙箱
*   - 空闲一段时间后自动挂起沙箱，把内存还回去
*   - 权限变更会重启沙箱，避免插件握着已撤销的能力继续跑
*/
var ACTIVATION_BUDGET_MS = 4e3;
var COMPLETION_TIMEOUT_MS = 1500;
var IDLE_SUSPEND_MS = 6e4;
var IDLE_SWEEP_INTERVAL_MS = 15e3;
var NETWORK_TIMEOUT_MS = 8e3;
var MAX_NETWORK_BYTES = 524288;
/**
* 同时存活的沙箱上限。
*
* 这个数字来自实测：基准（bench:plugins-scale）量到**每个沙箱约 93 MB**，
* 20 个插件全激活要吃掉约 1.8 GB。真隔离的价格就是这么高 ——
* 没有上限的话，装 50 个插件就能把机器拖垮。
*
* 超过上限时按"最久未使用"挂起，有在飞请求的不会被挂起。
*/
var MAX_ACTIVE_SANDBOXES = Number(process.env.SPARKLE_MAX_ACTIVE_PLUGINS ?? 8);
/** 算法可能跑得久一些（比如 Floyd 或树形 DP），给足时间 */
var SOLVER_TIMEOUT_MS = 15e3;
var PluginHost = class {
	options;
	records = /* @__PURE__ */ new Map();
	broken = [];
	sandboxes = /* @__PURE__ */ new Map();
	/** webContents.id → 沙箱。用于校验"这条消息真的是那个插件发的" */
	sandboxByWebContents = /* @__PURE__ */ new Map();
	activating = /* @__PURE__ */ new Map();
	/** 渲染层的补全请求 id → 已转发给哪些插件的哪些内部请求 */
	cancelRoutes = /* @__PURE__ */ new Map();
	idleTimer = null;
	initialized = false;
	constructor(options) {
		this.options = options;
	}
	async initialize() {
		if (this.initialized) return;
		this.initialized = true;
		const { records, broken } = await discoverPlugins(this.options.roots);
		this.records.clear();
		for (const record of records) {
			this.records.set(record.manifest.id, record);
			this.options.registerOrigin(record.manifest.id, record.directory);
		}
		this.broken = broken;
		this.registerIpc();
		this.startIdleSweeper();
	}
	list() {
		return {
			plugins: [...this.records.values()].map(summarize),
			broken: this.broken
		};
	}
	setGranted(id, requested) {
		const record = this.records.get(id);
		if (!record) return this.list();
		const next = intersectGranted(record.manifest, requested);
		const changed = next.length !== record.granted.length || next.some((p) => !record.granted.includes(p));
		record.granted = next;
		if (changed && this.sandboxes.has(id)) this.deactivate(id);
		this.push();
		return this.list();
	}
	requirePermission(record, permission) {
		if (!record.granted.includes(permission)) throw new Error(`插件「${record.manifest.name}」没有 ${permission} 权限。请在插件面板里查看它申请的权限并授权。`);
	}
	async activate(id, reason = "manual") {
		const record = this.records.get(id);
		if (!record) throw new Error(`未找到插件 ${id}`);
		if (this.sandboxes.get(id)?.alive) return;
		const running = this.activating.get(id);
		if (running) return running;
		const task = this.doActivate(record, reason).finally(() => this.activating.delete(id));
		this.activating.set(id, task);
		return task;
	}
	async doActivate(record, reason) {
		const id = record.manifest.id;
		record.state = "activating";
		record.error = void 0;
		this.push();
		const sandbox = new PluginSandbox(id, record.manifest.main, this.options.preloadPath, partitionForPlugin(id), {
			onReady: () => {
				record.lastActiveAt = Date.now();
			},
			onFatal: (message) => this.recordError(record, `插件初始化失败：${message}`),
			onLog: (message) => {
				console.log(`[plugin:${id}] ${message}`);
				this.options.onPluginLog?.(id, message);
			},
			onGone: (detail) => this.recordError(record, detail),
			onRegistered: (kind, value) => {
				record.lastActiveAt = Date.now();
				if (kind === "completions") console.log(`[plugin:${id}] 注册了 ${value} 的补全提供者`);
				else if (kind === "solver") {
					try {
						const parsed = JSON.parse(value);
						if (typeof parsed.id === "string") record.solvers.set(parsed.id, value);
					} catch {
						console.log(`[plugin:${id}] 求解器元数据无法解析，已忽略`);
					}
					console.log(`[plugin:${id}] 注册了求解器`);
				}
			},
			onDebug: (event) => this.options.onPluginDebug?.(`${id}: ${event}`)
		});
		this.sandboxes.set(id, sandbox);
		this.options.prepareSession(sandbox.partition);
		const startPromise = sandbox.start();
		const webContentsId = sandbox.webContentsId;
		if (webContentsId !== null) this.sandboxByWebContents.set(webContentsId, sandbox);
		try {
			await Promise.race([startPromise, new Promise((_, reject) => setTimeout(() => reject(/* @__PURE__ */ new Error(`激活超时（${ACTIVATION_BUDGET_MS} ms）`)), ACTIVATION_BUDGET_MS))]);
			record.state = "active";
			record.sandboxAlive = true;
			record.lastActiveAt = Date.now();
			console.log(`[plugin:${id}] 已激活（触发原因：${reason}）`);
			this.enforceActiveLimit(id);
		} catch (error) {
			this.recordError(record, error instanceof Error ? error.message : String(error));
			this.teardownSandbox(id);
		}
		this.push();
	}
	deactivate(id) {
		const record = this.records.get(id);
		this.teardownSandbox(id);
		if (record) {
			record.state = "inactive";
			record.sandboxAlive = false;
		}
		this.push();
	}
	/**
	* 活跃沙箱超限时，按"最久未使用"挂起。
	* 刚激活的那个不挂；有在飞请求的也不挂 —— 否则会把正在算的补全掐断。
	*/
	enforceActiveLimit(justActivated) {
		const alive = [...this.sandboxes.entries()].filter(([, sandbox]) => sandbox.alive);
		if (alive.length <= MAX_ACTIVE_SANDBOXES) return;
		const victims = alive.filter(([id, sandbox]) => id !== justActivated && sandbox.pendingCount === 0).map(([id]) => ({
			id,
			lastActiveAt: this.records.get(id)?.lastActiveAt ?? 0
		})).sort((a, b) => a.lastActiveAt - b.lastActiveAt);
		const excess = alive.length - MAX_ACTIVE_SANDBOXES;
		for (let index = 0; index < excess && index < victims.length; index += 1) {
			const victim = victims[index];
			console.log(`[plugin:${victim.id}] 活跃沙箱超过上限 ${MAX_ACTIVE_SANDBOXES}，自动挂起以回收内存`);
			this.deactivate(victim.id);
		}
	}
	teardownSandbox(id) {
		const sandbox = this.sandboxes.get(id);
		if (!sandbox) return;
		const webContentsId = sandbox.webContentsId;
		if (webContentsId !== null) this.sandboxByWebContents.delete(webContentsId);
		sandbox.destroy();
		this.sandboxes.delete(id);
	}
	disposeAll() {
		if (this.idleTimer) {
			clearInterval(this.idleTimer);
			this.idleTimer = null;
		}
		for (const id of [...this.sandboxes.keys()]) this.teardownSandbox(id);
	}
	startIdleSweeper() {
		this.idleTimer = setInterval(() => {
			const now = Date.now();
			for (const [id, sandbox] of this.sandboxes) {
				const record = this.records.get(id);
				if (!record) continue;
				if (sandbox.pendingCount > 0) continue;
				if (now - record.lastActiveAt > IDLE_SUSPEND_MS) {
					console.log(`[plugin:${id}] 空闲超时，自动挂起`);
					this.deactivate(id);
				}
			}
		}, IDLE_SWEEP_INTERVAL_MS);
		this.idleTimer.unref?.();
	}
	/**
	* 列出所有插件注册的求解器。
	*
	* 注意：插件是**懒激活**的，没激活过的插件还没有注册任何东西。
	* 所以这里要把声明过求解器能力的插件先激活一次 ——
	* 否则用户打开面板会看到一片空白，以为插件坏了。
	*/
	async listSolvers() {
		const withSolvers = [...this.records.values()].filter((record) => record.state !== "error" && (record.solvers.size > 0 || record.state !== "active"));
		await Promise.all(withSolvers.map((record) => this.activate(record.manifest.id, "onSolverPanel").catch(() => {})));
		const result = [];
		for (const record of this.records.values()) for (const metadata of record.solvers.values()) try {
			const parsed = JSON.parse(metadata);
			const id = String(parsed.id ?? "");
			const title = String(parsed.title ?? "");
			if (!id || !title) continue;
			result.push({
				pluginId: record.manifest.id,
				pluginName: record.manifest.name,
				id,
				title,
				description: String(parsed.description ?? ""),
				category: String(parsed.category ?? "其它"),
				inputs: Array.isArray(parsed.inputs) ? parsed.inputs.slice(0, 12) : []
			});
		} catch {}
		result.sort((left, right) => {
			if (left.category !== right.category) return left.category.localeCompare(right.category);
			return left.title.localeCompare(right.title);
		});
		return result;
	}
	/** 跑一个求解器。输入与输出都要过一遍清洗，因为插件不可信。 */
	async runSolver(pluginId, solverId, inputs) {
		const record = this.records.get(pluginId);
		if (!record) throw new Error(`找不到插件 ${pluginId}`);
		if (record.state === "error") throw new Error(`插件「${record.manifest.name}」处于错误状态：${record.error ?? "未知原因"}`);
		await this.activate(pluginId, "onSolverPanel");
		const sandbox = this.sandboxes.get(pluginId);
		if (!sandbox?.alive) throw new Error(`插件「${record.manifest.name}」的沙箱没有启动成功`);
		const safeInputs = {};
		for (const [key, value] of Object.entries(inputs ?? {})) safeInputs[String(key).slice(0, 40)] = String(value ?? "").slice(0, 2e4);
		const { result } = sandbox.request("runSolver", {
			solverId,
			inputs: safeInputs
		}, SOLVER_TIMEOUT_MS);
		try {
			return sanitizeSolverResult(await result);
		} catch (error) {
			throw new Error(`求解失败：${error instanceof Error ? error.message : String(error)}`);
		}
	}
	/** 哪些插件可能提供该语言的补全：已注册的 + 声明了 onLanguage 的 */
	providersFor(languageId) {
		const result = [];
		for (const record of this.records.values()) {
			const registered = this.sandboxes.get(record.manifest.id)?.completionLanguages.has(languageId) ?? false;
			const declares = shouldActivate(record.manifest, `onLanguage:${languageId}`);
			if (registered || declares) result.push(record);
		}
		return result;
	}
	async provideCompletions(outerRequestId, languageId, context) {
		const started = Date.now();
		const candidates = this.providersFor(languageId);
		if (candidates.length === 0) return {
			items: [],
			providers: [],
			noProvider: true,
			elapsedMs: 0
		};
		await Promise.all(candidates.map((record) => this.activate(record.manifest.id, `onLanguage:${languageId}`)));
		const active = candidates.filter((record) => this.sandboxes.get(record.manifest.id)?.alive);
		const routes = [];
		this.cancelRoutes.set(outerRequestId, routes);
		const safeContext = {
			languageId: String(context?.languageId ?? languageId),
			linePrefix: String(context?.linePrefix ?? "").slice(0, 4e3),
			lineNumber: Number(context?.lineNumber ?? 1) || 1,
			precedingLines: Array.isArray(context?.precedingLines) ? context.precedingLines.slice(-40).map((line) => String(line).slice(0, 2e3)) : []
		};
		try {
			const answers = await Promise.all(active.map(async (record) => {
				const { requestId, result } = this.sandboxes.get(record.manifest.id).request("provideCompletions", {
					languageId,
					context: safeContext
				}, COMPLETION_TIMEOUT_MS);
				routes.push({
					pluginId: record.manifest.id,
					requestId
				});
				try {
					const value = await result;
					return {
						pluginId: record.manifest.id,
						items: sanitizeCompletionItems(value)
					};
				} catch (error) {
					console.warn(`[plugin:${record.manifest.id}] 补全失败：${error instanceof Error ? error.message : String(error)}`);
					return {
						pluginId: record.manifest.id,
						items: []
					};
				}
			}));
			return {
				items: answers.flatMap((answer) => answer.items),
				providers: answers.filter((answer) => answer.items.length > 0).map((a) => a.pluginId),
				noProvider: false,
				elapsedMs: Date.now() - started
			};
		} finally {
			this.cancelRoutes.delete(outerRequestId);
		}
	}
	/** 把取消一路传给插件。返回是否找到了对应的请求。 */
	cancel(outerRequestId) {
		const routes = this.cancelRoutes.get(outerRequestId);
		if (!routes || routes.length === 0) return false;
		for (const route of routes) this.sandboxes.get(route.pluginId)?.cancel(route.requestId);
		return true;
	}
	registerIpc() {
		electron.ipcMain.handle(PLUGIN_CHANNELS.list, () => this.list());
		electron.ipcMain.handle(PLUGIN_CHANNELS.setGranted, (_event, id, permissions) => this.setGranted(id, permissions));
		electron.ipcMain.handle(PLUGIN_CHANNELS.activate, async (_event, id) => {
			await this.activate(id, "manual");
			return this.list();
		});
		electron.ipcMain.handle(PLUGIN_CHANNELS.deactivate, (_event, id) => {
			this.deactivate(id);
			return this.list();
		});
		electron.ipcMain.handle(PLUGIN_CHANNELS.provideCompletions, (_event, payload) => this.provideCompletions(payload.requestId, payload.languageId, payload.context));
		electron.ipcMain.handle(PLUGIN_CHANNELS.cancel, (_event, requestId) => this.cancel(requestId));
		electron.ipcMain.handle(PLUGIN_CHANNELS.listSolvers, () => this.listSolvers());
		electron.ipcMain.handle(PLUGIN_CHANNELS.runSolver, (_event, payload) => this.runSolver(payload.pluginId, payload.solverId, payload.inputs ?? {}));
		electron.ipcMain.on(PLUGIN_CHANNELS.sandboxReady, (event) => {
			this.sandboxFor(event)?.markReady();
		});
		electron.ipcMain.on(PLUGIN_CHANNELS.sandboxReply, (event, reply) => {
			this.sandboxFor(event)?.handleReply(reply);
		});
		electron.ipcMain.on(PLUGIN_CHANNELS.sandboxRegistered, (event, payload) => {
			this.sandboxFor(event)?.handleRegistered(payload?.kind ?? "", payload?.value ?? "");
		});
		electron.ipcMain.on(PLUGIN_CHANNELS.sandboxFatal, (event, message) => {
			const sandbox = this.sandboxFor(event);
			const record = sandbox ? this.records.get(sandbox.pluginId) : void 0;
			if (record) this.recordError(record, `插件初始化失败：${String(message).slice(0, 800)}`);
		});
		electron.ipcMain.on(PLUGIN_CHANNELS.sandboxLog, (event, message) => {
			const pluginId = this.sandboxFor(event)?.pluginId ?? "?";
			const text = String(message).slice(0, 500);
			console.log(`[plugin:${pluginId}] ${text}`);
			this.options.onPluginLog?.(pluginId, text);
		});
		electron.ipcMain.handle(PLUGIN_CHANNELS.sandboxRequest, (event, payload) => this.handleCapability(event, payload));
	}
	/**
	* 找出消息来源对应的沙箱。
	* **这是权限模型的地基**：不校验来源的话，主窗口（或另一个插件）
	* 就能冒充某个插件去领取它的文件/网络权限。
	*/
	sandboxFor(event) {
		return this.sandboxByWebContents.get(event.sender.id);
	}
	async handleCapability(event, payload) {
		const sandbox = this.sandboxFor(event);
		if (!sandbox) throw new Error("拒绝调用：来源不是已注册的插件沙箱");
		const record = this.records.get(sandbox.pluginId);
		if (!record) throw new Error("插件记录已失效");
		record.lastActiveAt = Date.now();
		const method = String(payload?.method ?? "");
		const params = payload?.params ?? {};
		switch (method) {
			case "workspace.readFile": {
				this.requirePermission(record, "workspace:read");
				const root = this.options.currentWorkspaceRoot();
				if (!root) throw new Error("当前没有打开工作区");
				const file = await readFileContent$1(root, String(params.path ?? ""));
				return {
					content: file.content,
					bytes: file.bytes,
					truncated: file.truncated,
					binary: file.binary
				};
			}
			case "workspace.writeFile": {
				this.requirePermission(record, "workspace:write");
				const root = this.options.currentWorkspaceRoot();
				if (!root) throw new Error("当前没有打开工作区");
				return saveFile$1(root, String(params.path ?? ""), String(params.content ?? ""));
			}
			case "network.fetch":
				this.requirePermission(record, "network");
				return this.brokerFetch(String(params.url ?? ""), params);
			case "process.exec": throw new Error("process 权限尚未开放：本版本不代理启动本机程序");
			default: throw new Error(`未知的能力方法：${method}`);
		}
	}
	/**
	* 网络代理。
	*
	* 因为沙箱 CSP 是 connect-src 'none'，插件**根本无法自行联网** ——
	* 所有出网流量都必须经过这里，于是审计、限流、超时、体积上限
	* 都成了主进程说了算的事。
	*/
	async brokerFetch(url, params) {
		let parsed;
		try {
			parsed = new URL(url);
		} catch {
			throw new Error(`URL 非法：${url}`);
		}
		if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw new Error(`只允许 http/https，收到 ${parsed.protocol}`);
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), NETWORK_TIMEOUT_MS);
		try {
			const response = await fetch(parsed, {
				method: typeof params.method === "string" ? params.method.toUpperCase() : "GET",
				signal: controller.signal,
				headers: { "user-agent": "SparkleIDE/0.1 (+plugin)" }
			});
			const chunks = [];
			let total = 0;
			let truncated = false;
			if (response.body) {
				const reader = response.body.getReader();
				for (;;) {
					const { done, value } = await reader.read();
					if (done) break;
					if (!value) continue;
					total += value.byteLength;
					if (total > MAX_NETWORK_BYTES) {
						truncated = true;
						await reader.cancel();
						break;
					}
					chunks.push(Buffer.from(value));
				}
			}
			return {
				status: response.status,
				ok: response.ok,
				truncated,
				text: Buffer.concat(chunks).toString("utf8")
			};
		} finally {
			clearTimeout(timer);
		}
	}
	recordError(record, message) {
		record.state = "error";
		record.error = message;
		this.push();
	}
	push() {
		this.options.notifyRenderer(this.list());
	}
};
//#endregion
//#region src/main/bench.ts
/**
* 冷启动基准埋点。
*
* 时间基准取 process.uptime()，也就是主进程真实启动以来的毫秒数 ——
* 这样节点之间的差值反映的是"从进程启动算起"，而不是"从模块加载算起"。
* 模块加载本身也是冷启动的一部分，用模块内 Date.now() 会把它漏掉。
*/
var benchEnabled = process.env.SPARKLE_BENCH === "1";
var marks = {};
var rendererInfo = null;
/** 渲染层自报的耗时（它自己的 performance.now 时间轴） */
var rendererMarks = {};
/** 各进程类型的内存占用（MB） */
var memoryMb = null;
/** 滚动时的帧间隔统计（毫秒） */
var scrollStats = null;
/** 基准过程里的诊断信息。基准失败时必须能看出"卡在哪一步"，而不是只看到失败 */
var diagnostics = {};
function recordDiagnostic(key, value) {
	diagnostics[key] = value;
}
function recordMemory(info) {
	memoryMb = info;
}
function recordScrollFrames(frames) {
	if (frames.length === 0) return;
	const sorted = [...frames].sort((a, b) => a - b);
	const pick = (ratio) => Math.round(sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * ratio))] * 10) / 10;
	scrollStats = {
		median: pick(.5),
		p95: pick(.95),
		worst: Math.round(sorted[sorted.length - 1] * 10) / 10,
		frames: frames.length
	};
}
function recordRendererMark(mark) {
	if (typeof mark?.name === "string" && typeof mark?.ms === "number") rendererMarks[mark.name] = Math.round(mark.ms);
}
/** 基准模式要驱动界面进入待测状态，所以把配置告诉渲染层 */
function benchConfig() {
	return {
		enabled: benchEnabled,
		workspace: process.env.SPARKLE_BENCH_WORKSPACE ?? null,
		openFile: process.env.SPARKLE_BENCH_OPEN ?? null,
		view: process.env.SPARKLE_BENCH_VIEW ?? null
	};
}
/** 记录渲染层自报的数据（performance.now 时间轴，与主进程不同源，仅作交叉参考） */
function recordRendererInfo(info) {
	if (info && typeof info.rendererMs === "number") rendererInfo = { rendererMs: info.rendererMs };
}
function now() {
	return Math.round(process.uptime() * 1e3);
}
function mark(name) {
	if (!(name in marks)) marks[name] = now();
}
function buildPayload() {
	return {
		marks: {
			...marks,
			quit: now()
		},
		totalMs: now(),
		renderer: rendererInfo,
		rendererMarks: { ...rendererMarks },
		memoryMb,
		scroll: scrollStats,
		diagnostics: { ...diagnostics },
		electron: process.versions.electron ?? "unknown",
		chrome: process.versions.chrome ?? "unknown",
		node: process.versions.node,
		platform: process.platform,
		arch: process.arch
	};
}
function reportAndQuit(app) {
	const payload = buildPayload();
	const json = JSON.stringify(payload);
	console.log("SPARKLE_BENCH_RESULT " + json);
	const outFile = process.env.SPARKLE_BENCH_OUT;
	if (outFile) try {
		(0, node_fs.writeFileSync)(outFile, JSON.stringify(payload, null, 2), "utf8");
	} catch (error) {
		console.error("基准结果写入失败:", error);
	}
	app.quit();
}
//#endregion
//#region src/main/interpreter.ts
var CANDIDATES = [
	{
		invocation: "py -3",
		command: "py",
		args: ["-3"]
	},
	{
		invocation: "python",
		command: "python",
		args: []
	},
	{
		invocation: "python3",
		command: "python3",
		args: []
	}
];
var UNAVAILABLE = {
	available: false,
	version: "",
	executable: "",
	invocation: ""
};
var cached$2;
function tryCandidate(candidate) {
	const versionRun = (0, node_child_process.spawnSync)(candidate.command, [...candidate.args, "--version"], {
		encoding: "utf8",
		timeout: 15e3,
		windowsHide: true
	});
	if (versionRun.error || versionRun.status !== 0) return null;
	const versionMatch = `${versionRun.stdout ?? ""}${versionRun.stderr ?? ""}`.trim().match(/(\d+\.\d+\.\d+)/);
	if (!versionMatch) return null;
	const execRun = (0, node_child_process.spawnSync)(candidate.command, [
		...candidate.args,
		"-c",
		"import sys; print(sys.executable)"
	], {
		encoding: "utf8",
		timeout: 15e3,
		windowsHide: true
	});
	if (execRun.error || execRun.status !== 0) return null;
	const executable = (execRun.stdout ?? "").trim();
	if (!executable) return null;
	return {
		available: true,
		version: versionMatch[1],
		executable,
		invocation: candidate.invocation,
		command: candidate.command,
		args: candidate.args
	};
}
/** 找到第一个真正可用的解释器。结果会缓存。 */
function resolveInterpreter(force = false) {
	if (!force && cached$2 !== void 0) return cached$2;
	for (const candidate of CANDIDATES) {
		const found = tryCandidate(candidate);
		if (found) {
			cached$2 = found;
			return found;
		}
	}
	cached$2 = null;
	return null;
}
/** 给渲染层看的安全信息（不带内部命令细节） */
function interpreterInfo(force = false) {
	const resolved = resolveInterpreter(force);
	if (!resolved) return UNAVAILABLE;
	return {
		available: true,
		version: resolved.version,
		executable: resolved.executable,
		invocation: resolved.invocation
	};
}
var MAX_TIMEOUT_MS = 12e4;
function clampTimeout(value, fallback) {
	if (typeof value !== "number" || !Number.isFinite(value)) return fallback;
	return Math.min(MAX_TIMEOUT_MS, Math.max(500, Math.round(value)));
}
/**
* 杀掉整棵进程树。
* 只 kill 直接子进程不够 —— Python 自己再 spawn 出来的子进程会变成孤儿继续跑。
*/
function killTree(child) {
	if (child.pid == null || child.exitCode !== null) return;
	if (process.platform === "win32") (0, node_child_process.spawnSync)("taskkill", [
		"/pid",
		String(child.pid),
		"/T",
		"/F"
	], {
		stdio: "ignore",
		windowsHide: true
	});
	else child.kill("SIGKILL");
}
var RunManager = class {
	callbacks;
	runs = /* @__PURE__ */ new Map();
	maxOutputBytes;
	defaultTimeoutMs;
	constructor(callbacks, options = {}) {
		this.callbacks = callbacks;
		this.maxOutputBytes = options.maxOutputBytes ?? 524288;
		this.defaultTimeoutMs = options.defaultTimeoutMs ?? 1e4;
	}
	get activeCount() {
		return this.runs.size;
	}
	start(request) {
		const interpreter = resolveInterpreter();
		if (!interpreter) throw new Error("未找到可用的 Python 解释器。请安装 Python 后重试。");
		const runId = (0, node_crypto.randomUUID)();
		const workDir = (0, node_fs.mkdtempSync)((0, node_path.join)((0, node_os.tmpdir)(), "sparkle-run-"));
		const sourceFile = (0, node_path.join)(workDir, "main.py");
		(0, node_fs.writeFileSync)(sourceFile, request.source, "utf8");
		const timeoutMs = clampTimeout(request.timeoutMs, this.defaultTimeoutMs);
		const child = (0, node_child_process.spawn)(interpreter.command, [...interpreter.args, sourceFile], {
			cwd: workDir,
			windowsHide: true,
			stdio: [
				"ignore",
				"pipe",
				"pipe"
			],
			env: {
				...process.env,
				PYTHONUTF8: "1",
				PYTHONIOENCODING: "utf-8",
				PYTHONUNBUFFERED: "1"
			}
		});
		const run = {
			runId,
			child,
			workDir,
			startedAt: Date.now(),
			timer: setTimeout(() => {
				run.timedOut = true;
				killTree(child);
			}, timeoutMs),
			timedOut: false,
			stdoutBytes: 0,
			stderrBytes: 0,
			stdoutTruncated: false,
			stderrTruncated: false,
			stdoutDecoder: new node_string_decoder.StringDecoder("utf8"),
			stderrDecoder: new node_string_decoder.StringDecoder("utf8"),
			finished: false
		};
		this.runs.set(runId, run);
		child.stdout?.on("data", (buffer) => this.forward(run, "stdout", buffer));
		child.stderr?.on("data", (buffer) => this.forward(run, "stderr", buffer));
		child.on("error", (error) => {
			this.callbacks.onStderr({
				runId,
				text: `无法启动解释器：${error.message}\n`
			});
		});
		child.on("close", (code, signal) => {
			this.finish(run, code, signal);
		});
		return {
			runId,
			interpreter: `Python ${interpreter.version} (${interpreter.invocation})`
		};
	}
	stop(runId) {
		const run = this.runs.get(runId);
		if (!run) return false;
		killTree(run.child);
		return true;
	}
	stopAll() {
		for (const run of this.runs.values()) killTree(run.child);
	}
	forward(run, stream, buffer) {
		if (stream === "stdout" ? run.stdoutTruncated : run.stderrTruncated) return;
		const used = stream === "stdout" ? run.stdoutBytes : run.stderrBytes;
		const remaining = this.maxOutputBytes - used;
		const overflow = buffer.length > remaining;
		const payload = overflow ? buffer.subarray(0, Math.max(0, remaining)) : buffer;
		if (payload.length > 0) {
			let text = (stream === "stdout" ? run.stdoutDecoder : run.stderrDecoder).write(payload);
			if (stream === "stdout") run.stdoutBytes += payload.length;
			else {
				run.stderrBytes += payload.length;
				text = this.tidyStderr(run, text);
			}
			if (text) {
				if (stream === "stdout") this.callbacks.onStdout({
					runId: run.runId,
					text
				});
				else this.callbacks.onStderr({
					runId: run.runId,
					text
				});
			}
		}
		if (overflow) {
			if (stream === "stdout") run.stdoutTruncated = true;
			else run.stderrTruncated = true;
			const limitKb = Math.round(this.maxOutputBytes / 1024);
			this.callbacks.onStderr({
				runId: run.runId,
				text: `\n[输出超过 ${limitKb} KB 已截断 —— 检查是否有停不下来的循环]\n`
			});
		}
	}
	/** 把临时目录路径从 traceback 里抹掉，初学者不需要看到 Temp 路径 */
	tidyStderr(run, text) {
		if (!text) return text;
		return text.split(run.workDir + node_path.sep).join("").split(run.workDir + "/").join("");
	}
	finish(run, code, signal) {
		if (run.finished) return;
		run.finished = true;
		clearTimeout(run.timer);
		this.runs.delete(run.runId);
		const tailOut = run.stdoutDecoder.end();
		if (tailOut) this.callbacks.onStdout({
			runId: run.runId,
			text: tailOut
		});
		const tailErr = run.stderrDecoder.end();
		if (tailErr) this.callbacks.onStderr({
			runId: run.runId,
			text: this.tidyStderr(run, tailErr)
		});
		this.callbacks.onFinished({
			runId: run.runId,
			exitCode: code,
			signal: signal ?? null,
			durationMs: Date.now() - run.startedAt,
			timedOut: run.timedOut,
			stdoutTruncated: run.stdoutTruncated,
			stderrTruncated: run.stderrTruncated
		});
		try {
			(0, node_fs.rmSync)(run.workDir, {
				recursive: true,
				force: true
			});
		} catch {}
	}
};
//#endregion
//#region src/shared/run.ts
/** IPC 通道名集中定义，避免两端写错字符串 */
var RUN_CHANNELS = {
	start: "run:start",
	stop: "run:stop",
	stdout: "run:stdout",
	stderr: "run:stderr",
	finished: "run:finished",
	interpreter: "run:interpreter"
};
//#endregion
//#region src/shared/bench.ts
var BENCH_CHANNELS = {
	config: "bench:config",
	mark: "bench:mark",
	rendererReady: "bench:renderer-ready"
};
//#endregion
//#region src/main/workspace.ts
/**
* 工作区：持有根目录，把相对路径的操作转发给纯文件层（fileService）。
*
* 这个模块是唯一 import electron 的地方（需要弹"打开文件夹"对话框），
* 所以刻意做得非常薄 —— 真正有逻辑的部分都在可测试的 fileService 里。
*/
var workspaceRoot = null;
function currentWorkspace() {
	return {
		root: workspaceRoot,
		name: workspaceRoot ? (0, node_path.basename)(workspaceRoot) : ""
	};
}
/** 基准测试用：不经对话框直接设定工作区根目录 */
function setWorkspaceRoot(directory) {
	workspaceRoot = (0, node_path.resolve)(directory);
	return currentWorkspace();
}
async function openFolder(window) {
	const options = {
		title: "打开文件夹",
		properties: ["openDirectory"]
	};
	const result = window ? await electron.dialog.showOpenDialog(window, options) : await electron.dialog.showOpenDialog(options);
	if (result.canceled || result.filePaths.length === 0) return currentWorkspace();
	workspaceRoot = (0, node_path.resolve)(result.filePaths[0]);
	return currentWorkspace();
}
function requireRoot() {
	if (!workspaceRoot) throw new Error("尚未打开文件夹");
	return workspaceRoot;
}
function readDirectory(relativePath) {
	return readDirectory$1(requireRoot(), relativePath);
}
function readFileContent(relativePath) {
	return readFileContent$1(requireRoot(), relativePath);
}
function saveFile(relativePath, content) {
	return saveFile$1(requireRoot(), relativePath, content);
}
//#endregion
//#region src/shared/toolchain.ts
var TOOLCHAIN_CHANNELS = {
	detect: "toolchain:detect",
	install: "toolchain:install",
	cancel: "toolchain:cancel",
	remove: "toolchain:remove",
	progress: "toolchain:progress",
	openFolder: "toolchain:openFolder",
	/** 手动指定编译器/解释器路径 */
	setManualPath: "toolchain:setManualPath",
	/** 打开系统文件选择框挑一个可执行文件 */
	browse: "toolchain:browse",
	/** 记住用户选了哪个候选 */
	selectCandidate: "toolchain:selectCandidate"
};
//#endregion
//#region src/main/toolchain/config.ts
function configPath() {
	return (0, node_path.join)(electron.app.getPath("userData"), "toolchain.json");
}
var cached$1 = null;
function loadToolchainConfig() {
	if (cached$1) return cached$1;
	try {
		const raw = (0, node_fs.readFileSync)(configPath(), "utf8");
		const parsed = JSON.parse(raw);
		cached$1 = typeof parsed === "object" && parsed !== null ? parsed : {};
	} catch {
		cached$1 = {};
	}
	return cached$1;
}
function saveToolchainConfig(update) {
	const next = {
		...loadToolchainConfig(),
		...update
	};
	cached$1 = next;
	try {
		const file = configPath();
		(0, node_fs.mkdirSync)((0, node_path.dirname)(file), { recursive: true });
		(0, node_fs.writeFileSync)(file, JSON.stringify(next, null, 2), "utf8");
	} catch (error) {
		console.error("保存工具链配置失败：", error);
	}
	return next;
}
function clearToolchainConfig() {
	cached$1 = {};
	try {
		(0, node_fs.writeFileSync)(configPath(), "{}", "utf8");
	} catch {}
	return cached$1;
}
/** 手动指定的路径是否还有效（用户可能把编译器删了） */
function isValidExecutable(path) {
	return typeof path === "string" && path.length > 0 && (0, node_fs.existsSync)(path);
}
//#endregion
//#region src/main/toolchain/catalog.ts
var TOOL_PACKAGES = {
	gcc: {
		id: "gcc",
		name: "MinGW-w64 GCC (WinLibs)",
		version: "16.2.0",
		url: "https://github.com/brechtsanders/winlibs_mingw/releases/download/16.2.0posix-14.0.0-ucrt-r2/winlibs-x86_64-posix-seh-gcc-16.2.0-mingw-w64ucrt-14.0.0-r2.7z",
		approximateBytes: 109762824,
		archive: "7z",
		probeRelative: "bin/g++.exe",
		probeArgs: ["--version"],
		versionPattern: "(\\d+\\.\\d+\\.\\d+)"
	},
	python: {
		id: "python",
		name: "Python (免安装版)",
		version: "3.13.7",
		url: "https://www.python.org/ftp/python/3.13.7/python-3.13.7-embed-amd64.zip",
		approximateBytes: 109e5,
		archive: "zip",
		probeRelative: "python.exe",
		probeArgs: ["--version"],
		versionPattern: "(\\d+\\.\\d+\\.\\d+)"
	}
};
var PURPOSE_LABELS = {
	gcc: "编译 C++ 程序（节点图、一键编译都要用它）",
	python: "运行 Python 程序（含免安装版，不污染系统）",
	cmake: "生成构建文件。本机已经装好了"
};
//#endregion
//#region src/main/toolchain/discover.ts
/**
* 自动发现机器上已装的 C++ 编译器。
*
* 为什么这是主路径而不是"下载"：
*   本机实测就有三份 MinGW（GCC 12.2 / 8.2 / TDM 4.9），全在 I 盘。
*   要求用户为了用一个已经存在的编译器再去下 47 MB，是没道理的。
*   下载只在"确实一个都没有"时兜底。
*
* 发现的难点在于**目录布局五花八门**：
*   I:\mingw64-12.x\mingw64\bin\g++.exe   ← 多套一层
*   I:\Mingw\bin\g++.exe                  ← 直接就是根
*   I:\Dev-Cpp\MinGW64\bin\g++.exe        ← 藏在 Dev-C++ 里
* 所以不能只按固定路径找，要按"标志文件"在候选目录里搜几层。
*/
/** 目录名像编译器的，才值得进去看 */
var INTERESTING_DIR = /^(mingw|mingw32|mingw64|mingw-w64|tdm-?gcc|tdm64|msys|msys2|msys64|w64devkit|dev-?cpp|devcpp|codeblocks|winlibs|llvm|clang|qt|tools?|dev|apps?|programs?|program files( \(x86\))?|msys32|ucrt64|clang64)/i;
/** 编译器根目录下常见的 bin 位置（相对候选目录） */
var BIN_CANDIDATES = [
	"bin",
	"mingw64/bin",
	"mingw32/bin",
	"MinGW64/bin",
	"x86_64-w64-mingw32/bin",
	"ucrt64/bin",
	"clang64/bin",
	(0, node_path.join)("..", "bin")
];
function runVersion(executable) {
	let result;
	try {
		result = (0, node_child_process.spawnSync)(executable, ["--version"], {
			encoding: "utf8",
			timeout: 15e3,
			windowsHide: true
		});
	} catch {
		return null;
	}
	const output = `${result.stdout ?? ""}${result.stderr ?? ""}`.trim();
	if (!output) return null;
	const firstLine = output.split(/\r?\n/)[0].trim();
	const matches = [...firstLine.matchAll(/(\d+)\.(\d+)\.(\d+)/g)];
	if (matches.length === 0) return null;
	const last = matches[matches.length - 1];
	return {
		version: `${last[1]}.${last[2]}.${last[3]}`,
		description: firstLine
	};
}
function toTuple(version) {
	return version.split(".").map((part) => Number.parseInt(part, 10) || 0);
}
/** 比较两个版本，大的排前面 */
function compareVersion(a, b) {
	for (let index = 0; index < Math.max(a.length, b.length); index += 1) {
		const left = a[index] ?? 0;
		const right = b[index] ?? 0;
		if (left !== right) return right - left;
	}
	return 0;
}
function probeCandidate(root) {
	for (const relative of BIN_CANDIDATES) {
		const binDir = (0, node_path.join)(root, relative);
		const executable = (0, node_path.join)(binDir, "g++.exe");
		if (!(0, node_fs.existsSync)(executable)) continue;
		const info = runVersion(executable);
		if (!info) continue;
		let makeExecutable = "";
		for (const name of ["mingw32-make.exe", "make.exe"]) {
			const candidate = (0, node_path.join)(binDir, name);
			if ((0, node_fs.existsSync)(candidate)) {
				makeExecutable = candidate;
				break;
			}
		}
		return {
			executable,
			binDir,
			root,
			version: info.version,
			versionTuple: toTuple(info.version),
			description: info.description,
			makeExecutable,
			hasMake: makeExecutable !== "",
			cmakeGenerator: makeExecutable ? "MinGW Makefiles" : "",
			source: "discovered"
		};
	}
	return null;
}
/**
* 列出某个目录下的子目录名。
*
* `withFileTypes: true` 可能抛 `UNKNOWN: unknown error, scandir 'X:\'`。
* 这里必须退回"只读名字再逐个 stat"，并把两层都写成 try ——
* 一旦把异常吞掉返回空数组，整个盘会被**静默跳过**，
* 表现就是"明明装了编译器却一个都没发现"。
*
* 曾经的错误解释（留在这里以免再犯）：本机一度把这种失败归因于
* "某个盘符的特性"甚至"沙箱限制"。真实原因是那个卷的 **NTFS 根目录索引
* （$I30）损坏**了 —— chkdsk 报出 "Bad subtree / 18 missing entries in
* index $I30 of directory \"，修好后同一份 readdirSync 立刻正常返回 258 项。
* 教训：看到 "损坏且无法读取" 这类字面报错就该去查文件系统，
* 不要用"环境限制"把它解释掉。
*/
function listDirectories(directory) {
	try {
		return (0, node_fs.readdirSync)(directory, { withFileTypes: true }).filter((entry) => entry.isDirectory()).map((entry) => entry.name);
	} catch {
		try {
			return (0, node_fs.readdirSync)(directory).filter((name) => {
				try {
					return (0, node_fs.statSync)((0, node_path.join)(directory, name)).isDirectory();
				} catch {
					return false;
				}
			});
		} catch {
			return [];
		}
	}
}
/**
* 在若干根目录里发现编译器。
*
* 为了不把启动卡住，只往下看有限几层，并且**只进入名字像编译器的目录** ——
* 全盘递归在用户的机器上可能要几十秒，而这是每次开界面都要做的事。
*/
function discoverCompilers(roots) {
	const found = [];
	const seen = /* @__PURE__ */ new Set();
	const seenExecutables = /* @__PURE__ */ new Set();
	const consider = (directory) => {
		if (seen.has(directory)) return;
		seen.add(directory);
		const compiler = probeCandidate(directory);
		if (!compiler) return;
		const key = compiler.executable.toLowerCase();
		if (seenExecutables.has(key)) return;
		seenExecutables.add(key);
		found.push(compiler);
	};
	for (const root of roots) {
		if (!(0, node_fs.existsSync)(root)) continue;
		const level1 = listDirectories(root);
		for (const name of level1) {
			if (!INTERESTING_DIR.test(name)) continue;
			const directory = (0, node_path.join)(root, name);
			consider(directory);
			for (const nested of listDirectories(directory)) if (INTERESTING_DIR.test(nested) || /^(mingw|bin|ucrt)/i.test(nested)) consider((0, node_path.join)(directory, nested));
		}
		for (const programFiles of ["Program Files", "Program Files (x86)"]) {
			const base = (0, node_path.join)(root, programFiles);
			if (!(0, node_fs.existsSync)(base)) continue;
			for (const name of listDirectories(base)) if (INTERESTING_DIR.test(name)) consider((0, node_path.join)(base, name));
		}
	}
	found.sort((a, b) => compareVersion(a.versionTuple, b.versionTuple));
	return found;
}
/** 默认要搜的根目录：所有固定磁盘的根 + 常见安装位置 */
function defaultSearchRoots() {
	const roots = [];
	for (let code = 65; code <= 90; code += 1) {
		const drive = `${String.fromCharCode(code)}:\\`;
		try {
			if ((0, node_fs.statSync)(drive).isDirectory()) roots.push(drive);
		} catch {}
	}
	return roots;
}
//#endregion
//#region src/main/toolchain/detect.ts
/**
* 工具链探测。
*
* **自动发现是主路径，下载只是兜底。** 本机实测就装着三份 MinGW
* （GCC 12.2 / 8.2 / TDM 4.9），要求用户为了用一个已经存在的编译器再下 47MB
* 是没道理的。
*
* 优先级：手动指定 > 用户记住的选择 > 版本最高的一份
* （"版本最高"而不是"我们下载的那份"：用户机器上的 12.2 明显比我们能下的 8.1 好）
*
* 探测一律用 spawnSync 真跑一次 —— 只看文件存不存在是不够的，
* 之前就踩过"python3 是 0 字节 Store 存根"的坑。
*/
var MANAGED_PROBE = {
	gcc: (0, node_path.join)("bin", "g++.exe"),
	python: "python.exe"
};
function findManagedRoot(toolRoot, toolId, maxDepth = 4) {
	const base = (0, node_path.join)(toolRoot, toolId);
	if (!(0, node_fs.existsSync)(base)) return null;
	const queue = [{
		dir: base,
		depth: 0
	}];
	while (queue.length > 0) {
		const current = queue.shift();
		if ((0, node_fs.existsSync)((0, node_path.join)(current.dir, MANAGED_PROBE[toolId]))) return current.dir;
		if (current.depth >= maxDepth) continue;
		let entries;
		try {
			entries = (0, node_fs.readdirSync)(current.dir);
		} catch {
			continue;
		}
		for (const name of entries) {
			const child = (0, node_path.join)(current.dir, name);
			try {
				if ((0, node_fs.statSync)(child).isDirectory()) queue.push({
					dir: child,
					depth: current.depth + 1
				});
			} catch {}
		}
	}
	return null;
}
function probe(executable, args, pattern) {
	let result;
	try {
		result = (0, node_child_process.spawnSync)(executable, args, {
			encoding: "utf8",
			timeout: 15e3,
			windowsHide: true
		});
	} catch {
		return "";
	}
	const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
	return new RegExp(pattern).exec(output)?.[1] ?? "";
}
function findMake(binDir) {
	for (const name of ["mingw32-make.exe", "make.exe"]) {
		const candidate = (0, node_path.join)(binDir, name);
		if ((0, node_fs.existsSync)(candidate)) return candidate;
	}
	return "";
}
/** 把发现结果转成统一的候选结构 */
function toCandidate(compiler, source) {
	return {
		executable: compiler.executable,
		binDir: compiler.binDir,
		version: compiler.version,
		description: compiler.description,
		hasMake: compiler.hasMake,
		makeExecutable: compiler.makeExecutable,
		source
	};
}
/** 手动指定的 g++ 也要能凑出完整信息（不能只记一个路径） */
function candidateFromManual(executable) {
	if (!(0, node_fs.existsSync)(executable)) return null;
	const binDir = executable.replace(/[\\/][^\\/]+$/, "");
	const version = probe(executable, ["--version"], "(\\d+\\.\\d+\\.\\d+)");
	if (!version) return null;
	const description = (() => {
		try {
			return `${(0, node_child_process.spawnSync)(executable, ["--version"], {
				encoding: "utf8",
				timeout: 15e3,
				windowsHide: true
			}).stdout ?? ""}`.split(/\r?\n/)[0]?.trim() ?? "";
		} catch {
			return "";
		}
	})();
	const hasMake = ["mingw32-make.exe", "make.exe"].some((name) => (0, node_fs.existsSync)((0, node_path.join)(binDir, name)));
	return {
		executable,
		binDir,
		version,
		description,
		hasMake,
		makeExecutable: hasMake ? findMake(binDir) : "",
		source: "manual"
	};
}
function collectCompilers(options) {
	const candidates = [];
	const startedAt = Date.now();
	if (options.manualGccPath) {
		const manual = candidateFromManual(options.manualGccPath);
		if (manual) candidates.push(manual);
	}
	for (const root of [options.bundledRoot, options.toolRoot]) {
		if (!root) continue;
		const managedRoot = findManagedRoot(root, "gcc");
		if (!managedRoot) continue;
		const executable = (0, node_path.join)(managedRoot, MANAGED_PROBE.gcc);
		const version = probe(executable, ["--version"], "(\\d+\\.\\d+\\.\\d+)");
		if (!version) continue;
		const binDir = (0, node_path.join)(managedRoot, "bin");
		const makeExecutable = findMake(binDir);
		const bundled = root === options.bundledRoot;
		candidates.push({
			executable,
			binDir,
			version,
			description: bundled ? "随 Sparkle IDE 预装（开箱即用）" : "由 Sparkle IDE 下载安装",
			hasMake: makeExecutable !== "",
			makeExecutable,
			source: "managed"
		});
	}
	const searchRoots = options.searchRoots ?? defaultSearchRoots();
	if (options.discover !== false) for (const compiler of discoverCompilers(searchRoots)) candidates.push(toCandidate(compiler, "discovered"));
	const seen = /* @__PURE__ */ new Set();
	const unique = candidates.filter((candidate) => {
		const key = candidate.executable.toLowerCase();
		if (seen.has(key)) return false;
		seen.add(key);
		return true;
	});
	unique.sort((left, right) => {
		if (left.source === "manual" && right.source !== "manual") return -1;
		if (right.source === "manual" && left.source !== "manual") return 1;
		return compareVersion(left.version.split(".").map(Number), right.version.split(".").map(Number));
	});
	return {
		candidates: unique,
		searchRoots,
		elapsedMs: Date.now() - startedAt
	};
}
function detectTools(options) {
	const { candidates, searchRoots, elapsedMs } = collectCompilers(options);
	const selectedCompiler = (options.preferredGccPath ? candidates.find((candidate) => candidate.executable.toLowerCase() === options.preferredGccPath.toLowerCase()) : null) ?? candidates[0] ?? null;
	let pythonExecutable = "";
	let pythonVersion = "";
	let pythonSource = "missing";
	if (options.manualPythonPath && (0, node_fs.existsSync)(options.manualPythonPath)) {
		const version = probe(options.manualPythonPath, ["--version"], "(\\d+\\.\\d+\\.\\d+)");
		if (version) {
			pythonExecutable = options.manualPythonPath;
			pythonVersion = version;
			pythonSource = "manual";
		}
	}
	if (!pythonExecutable) for (const root of [options.bundledRoot, options.toolRoot]) {
		if (!root) continue;
		const managedRoot = findManagedRoot(root, "python");
		if (!managedRoot) continue;
		const executable = (0, node_path.join)(managedRoot, MANAGED_PROBE.python);
		const version = probe(executable, ["--version"], "(\\d+\\.\\d+\\.\\d+)");
		if (version) {
			pythonExecutable = executable;
			pythonVersion = version;
			pythonSource = "managed";
			break;
		}
	}
	if (!pythonExecutable) for (const [command, args] of [["py", ["-3", "--version"]], ["python", ["--version"]]]) {
		const version = probe(command, [...args], "(\\d+\\.\\d+\\.\\d+)");
		if (version) {
			pythonExecutable = command;
			pythonVersion = version;
			pythonSource = "system";
			break;
		}
	}
	let cmakeExecutable = "";
	let cmakeVersion = "";
	for (const executable of ["cmake", "C:\\Program Files\\CMake\\bin\\cmake.exe"]) {
		const version = probe(executable, ["--version"], "cmake version (\\d+\\.\\d+\\.\\d+)");
		if (version) {
			cmakeExecutable = executable;
			cmakeVersion = version;
			break;
		}
	}
	const offlineGcc = (0, node_fs.existsSync)((0, node_path.join)(options.toolRoot, "..", "vendor", "mingw-gcc-8.1.0-x86_64.7z"));
	return {
		tools: [
			{
				id: "gcc",
				name: selectedCompiler ? `MinGW-w64 GCC ${selectedCompiler.version}` : TOOL_PACKAGES.gcc.name,
				available: selectedCompiler !== null,
				version: selectedCompiler?.version ?? "",
				path: selectedCompiler?.executable ?? "",
				source: selectedCompiler ? selectedCompiler.source === "manual" ? "manual" : selectedCompiler.source === "managed" ? "managed" : "system" : "missing",
				installable: true,
				approximateBytes: TOOL_PACKAGES.gcc.approximateBytes,
				purpose: PURPOSE_LABELS.gcc,
				offlineArchive: offlineGcc,
				candidates
			},
			{
				id: "python",
				name: TOOL_PACKAGES.python.name,
				available: pythonExecutable !== "",
				version: pythonVersion,
				path: pythonExecutable,
				source: pythonSource,
				installable: true,
				approximateBytes: TOOL_PACKAGES.python.approximateBytes,
				purpose: PURPOSE_LABELS.python
			},
			{
				id: "cmake",
				name: "CMake",
				available: cmakeExecutable !== "",
				version: cmakeVersion,
				path: cmakeExecutable,
				source: cmakeExecutable ? "system" : "missing",
				installable: false,
				approximateBytes: 0,
				purpose: PURPOSE_LABELS.cmake
			}
		],
		compilers: candidates,
		selectedCompiler,
		searchRoots,
		elapsedMs
	};
}
//#endregion
//#region src/main/toolchain/installer.ts
/** 进度上报的最小间隔，避免每收一个 chunk 就发一次 IPC */
var PROGRESS_INTERVAL_MS = 200;
/** 单次连接的超时，避免网络卡住时一直挂着 */
var CONNECT_TIMEOUT_MS = 6e4;
/** 最多跟随几次重定向（SourceForge 会 302 到镜像站） */
var MAX_REDIRECTS = 6;
function report(context, toolId, phase, message, receivedBytes = 0, totalBytes = null) {
	context.onProgress({
		toolId,
		phase,
		ratio: totalBytes && totalBytes > 0 ? Math.min(1, receivedBytes / totalBytes) : null,
		receivedBytes,
		totalBytes,
		message
	});
}
/**
* 打开一个下载流，自动跟随重定向。
*
* **刻意不用 fetch。** 本机实测：用 fetch + Readable.fromWeb + pipeline 下载
* 47 MB 的 mingw 包时，数据能收完，但收尾时 Node 的 undici 会抛内部断言：
*
*   AssertionError: assert(!this.paused)
*     at Parser.finish (undici)  ← TLSSocket.onHttpSocketEnd
*
* 那是 undici 在"背压暂停"与"socket 结束"之间的竞态，属于它的内部缺陷。
* 下载编译器是关键路径，不能建在这上面。node:https 直接给出可读流，
* 既能精确报告 content-length 进度，也能用 pipeline 的 signal 干净地取消。
*/
function openStream(url, signal, depth = 0) {
	return new Promise((resolve, reject) => {
		if (depth > MAX_REDIRECTS) {
			reject(/* @__PURE__ */ new Error("重定向次数过多，下载地址可能有问题。"));
			return;
		}
		const request = (url.startsWith("https:") ? node_https.get : node_http.get)(url, { headers: { "user-agent": "SparkleIDE/0.1" } }, (response) => {
			const status = response.statusCode ?? 0;
			const location = response.headers.location;
			if (status >= 300 && status < 400 && location) {
				response.resume();
				const next = new URL(location, url).href;
				openStream(next, signal, depth + 1).then(resolve, reject);
				return;
			}
			if (status !== 200) {
				response.resume();
				reject(new Error(`HTTP ${status} ${response.statusMessage ?? ""}`.trim()));
				return;
			}
			const headerLength = Number(response.headers["content-length"]);
			resolve({
				stream: response,
				totalBytes: Number.isFinite(headerLength) && headerLength > 0 ? headerLength : null
			});
		});
		const onAbort = () => {
			request.destroy(/* @__PURE__ */ new Error("已取消"));
		};
		if (signal.aborted) onAbort();
		else {
			signal.addEventListener("abort", onAbort, { once: true });
			request.on("close", () => signal.removeEventListener("abort", onAbort));
		}
		request.on("error", (error) => reject(error instanceof Error ? error : new Error(String(error))));
		request.setTimeout(CONNECT_TIMEOUT_MS, () => {
			request.destroy(/* @__PURE__ */ new Error(`连接超时（${CONNECT_TIMEOUT_MS / 1e3} 秒无响应）`));
		});
	});
}
/** 流式下载到文件，同时上报进度并支持取消 */
async function downloadTo(url, targetPath, toolId, context, label) {
	const { stream, totalBytes } = await openStream(url, context.signal);
	let receivedBytes = 0;
	let lastReportAt = 0;
	stream.on("data", (chunk) => {
		receivedBytes += chunk.length;
		const now = Date.now();
		if (now - lastReportAt >= PROGRESS_INTERVAL_MS) {
			lastReportAt = now;
			report(context, toolId, "downloading", `${label} 下载中… ${(receivedBytes / 1024 / 1024).toFixed(1)} MB` + (totalBytes ? ` / ${(totalBytes / 1024 / 1024).toFixed(1)} MB` : ""), receivedBytes, totalBytes);
		}
	});
	await (0, node_stream_promises.pipeline)(stream, (0, node_fs.createWriteStream)(targetPath), { signal: context.signal });
	report(context, toolId, "downloading", `${label} 下载完成（${(receivedBytes / 1024 / 1024).toFixed(1)} MB）`, receivedBytes, totalBytes ?? receivedBytes);
}
/** 解压。zip 用系统自带的 bsdtar（实测支持 zip），7z 用随包收录的 7za */
function extractArchive(archivePath, targetDir, kind, sevenZipPath) {
	const result = kind === "7z" ? (0, node_child_process.spawnSync)(sevenZipPath, [
		"x",
		archivePath,
		`-o${targetDir}`,
		"-y"
	], {
		encoding: "utf8",
		windowsHide: true
	}) : (0, node_child_process.spawnSync)("tar", [
		"-xf",
		archivePath,
		"-C",
		targetDir
	], {
		encoding: "utf8",
		windowsHide: true
	});
	if (result.error) throw new Error(`解压失败：${result.error.message}`);
	if (result.status !== 0) {
		const detail = `${result.stderr ?? ""}${result.stdout ?? ""}`.trim().slice(0, 400);
		throw new Error(`解压失败（退出码 ${result.status}）${detail ? `：${detail}` : ""}`);
	}
}
/**
* 找到真正包含 probeRelative 的那一层目录。
*
* 不能假定解压后的层次：mingw 的包会多套一层 `mingw64/`，
* 而不同版本的包层次还可能不一样。所以按标志文件搜，最多找 4 层。
*/
async function findInstallRoot(directory, probeRelative, maxDepth = 4) {
	const queue = [{
		dir: directory,
		depth: 0
	}];
	while (queue.length > 0) {
		const current = queue.shift();
		const candidate = (0, node_path.join)(current.dir, probeRelative);
		try {
			if ((await (0, node_fs_promises.stat)(candidate)).isFile()) return current.dir;
		} catch {}
		if (current.depth >= maxDepth) continue;
		try {
			const entries = await (0, node_fs_promises.readdir)(current.dir, { withFileTypes: true });
			for (const entry of entries) if (entry.isDirectory()) queue.push({
				dir: (0, node_path.join)(current.dir, entry.name),
				depth: current.depth + 1
			});
		} catch {
			continue;
		}
	}
	return null;
}
/** 跑一次探测命令拿版本号 */
function probeVersion(executable, args, pattern) {
	const result = (0, node_child_process.spawnSync)(executable, args, {
		encoding: "utf8",
		timeout: 2e4,
		windowsHide: true
	});
	const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
	return new RegExp(pattern).exec(output)?.[1] ?? "";
}
/**
* 安装一个工具链。
* 流程：下载 → 解压 → 定位真实根目录 → 跑一次验证版本 → 清掉压缩包。
*/
async function installTool(toolId, context) {
	const pkg = TOOL_PACKAGES[toolId];
	if (!pkg) throw new Error(`不支持下载的工具：${toolId}`);
	report(context, toolId, "resolving", `准备下载 ${pkg.name} ${pkg.version}…`);
	const stagingDir = await (0, node_fs_promises.mkdtemp)((0, node_path.join)((0, node_os.tmpdir)(), `sparkle-tool-${toolId}-`));
	const archivePath = (0, node_path.join)(stagingDir, pkg.archive === "7z" ? "package.7z" : "package.zip");
	const targetDir = (0, node_path.resolve)(context.root, toolId);
	try {
		await downloadTo(pkg.url, archivePath, toolId, context, pkg.name);
		if (context.signal.aborted) throw new Error("已取消");
		report(context, toolId, "extracting", pkg.archive === "7z" ? "正在解压（大约需要十几秒）…" : "正在解压…");
		await (0, node_fs_promises.rm)(targetDir, {
			recursive: true,
			force: true
		});
		await (0, node_fs_promises.mkdir)(targetDir, { recursive: true });
		extractArchive(archivePath, targetDir, pkg.archive, context.sevenZipPath);
		report(context, toolId, "verifying", "正在检查安装结果…");
		const installRoot = await findInstallRoot(targetDir, pkg.probeRelative);
		if (!installRoot) throw new Error(`解压完成但没找到 ${pkg.probeRelative}。压缩包结构可能变了，请检查 ${targetDir}`);
		const executable = (0, node_path.join)(installRoot, pkg.probeRelative);
		const version = probeVersion(executable, pkg.probeArgs, pkg.versionPattern);
		if (!version) throw new Error(`找到了 ${pkg.probeRelative} 但执行失败，安装可能不完整。`);
		report(context, toolId, "done", `${pkg.name} ${version} 安装完成`);
		return {
			toolId,
			installRoot,
			executable,
			version
		};
	} finally {
		await (0, node_fs_promises.rm)(stagingDir, {
			recursive: true,
			force: true
		}).catch(() => {});
	}
}
//#endregion
//#region src/main/toolchain/index.ts
/**
* 工具链管理。
*
* 主路径是**自动发现**（用户机器上通常已经装了编译器），
* 下载只是兜底；手动指定是最后的安全网 ——
* 自动发现不可能覆盖所有情况，而且本机实测遇到过
* "沙箱禁止子进程列出盘符根目录"这类会让扫描漏掉整个盘的限制。
*/
var cached = null;
var activeInstall = null;
function toolRoot() {
	return (0, node_path.join)(electron.app.getPath("userData"), "toolchains");
}
/**
* 随应用一起发布的工具链目录。
* 打包时把编译器放进 `resources/app/toolchains/`，装完就能用，不用下载也不用发现。
*/
function bundledToolRoot() {
	return (0, node_path.join)(electron.app.getAppPath(), "toolchains");
}
/** 随包收录的 7za，用于解压 .7z */
function sevenZipPath() {
	return (0, node_path.join)(electron.app.getAppPath(), "vendor", "7za.exe");
}
function runDetect(force) {
	if (!force && cached) return cached;
	const config = loadToolchainConfig();
	const startedAt = Date.now();
	cached = detectTools({
		toolRoot: toolRoot(),
		bundledRoot: bundledToolRoot(),
		manualGccPath: isValidExecutable(config.manualGccPath) ? config.manualGccPath : void 0,
		manualPythonPath: isValidExecutable(config.manualPythonPath) ? config.manualPythonPath : void 0,
		preferredGccPath: config.preferredGccPath
	});
	console.log(`[toolchain] 探测完成：${Date.now() - startedAt} ms，找到 ${cached.compilers.length} 个编译器，选中 ${cached.selectedCompiler?.version ?? "（无）"}`);
	return cached;
}
function detect(force = false) {
	return runDetect(force).tools;
}
/**
* 供构建系统用：当前选中的编译器。
* 返回的不是纯字符串，因为**运行产物时必须要 bin 目录**（缺 DLL 会静默失败）。
*/
function currentCompiler() {
	return runDetect(false).selectedCompiler;
}
function registerToolchainIpc(notify, getWindow) {
	electron.ipcMain.handle(TOOLCHAIN_CHANNELS.detect, (_event, force) => runDetect(force === true).tools);
	electron.ipcMain.handle(TOOLCHAIN_CHANNELS.install, async (_event, toolId) => {
		if (activeInstall) return {
			ok: false,
			error: `已有安装任务在进行（${activeInstall.toolId}），请等它结束或取消它。`
		};
		const controller = new AbortController();
		activeInstall = {
			toolId,
			controller
		};
		try {
			await (0, node_fs_promises.mkdir)(toolRoot(), { recursive: true });
			const sevenZip = sevenZipPath();
			if (!(0, node_fs.existsSync)(sevenZip)) throw new Error(`缺少解压工具 ${sevenZip}。它在仓库的 vendor 目录下，打包时需要一起带上。`);
			const result = await installTool(toolId, {
				sevenZipPath: sevenZip,
				root: toolRoot(),
				onProgress: notify,
				signal: controller.signal
			});
			cached = null;
			return {
				ok: true,
				version: result.version,
				executable: result.executable
			};
		} catch (error) {
			const aborted = controller.signal.aborted;
			const message = aborted ? "已取消安装" : error instanceof Error ? error.message : String(error);
			notify({
				toolId,
				phase: aborted ? "cancelled" : "failed",
				ratio: null,
				receivedBytes: 0,
				totalBytes: null,
				message
			});
			return {
				ok: false,
				error: message,
				cancelled: aborted
			};
		} finally {
			activeInstall = null;
		}
	});
	electron.ipcMain.handle(TOOLCHAIN_CHANNELS.cancel, () => {
		if (!activeInstall) return false;
		activeInstall.controller.abort();
		return true;
	});
	electron.ipcMain.handle(TOOLCHAIN_CHANNELS.remove, async (_event, toolId) => {
		if (activeInstall?.toolId === toolId) return {
			ok: false,
			error: "该工具正在安装中，请先取消。"
		};
		await (0, node_fs_promises.rm)((0, node_path.join)(toolRoot(), toolId), {
			recursive: true,
			force: true
		});
		cached = null;
		return {
			ok: true,
			tools: detect(true)
		};
	});
	electron.ipcMain.handle(TOOLCHAIN_CHANNELS.openFolder, async () => {
		const directory = toolRoot();
		await (0, node_fs_promises.mkdir)(directory, { recursive: true });
		electron.shell.openPath(directory);
		return directory;
	});
	electron.ipcMain.handle(TOOLCHAIN_CHANNELS.browse, async (_event, toolId) => {
		const window = getWindow();
		const options = {
			title: toolId === "gcc" ? "选择 g++.exe" : "选择 python.exe",
			properties: ["openFile"],
			filters: toolId === "gcc" ? [{
				name: "C++ 编译器",
				extensions: ["exe"]
			}] : [{
				name: "Python 解释器",
				extensions: ["exe"]
			}]
		};
		const result = window ? await electron.dialog.showOpenDialog(window, options) : await electron.dialog.showOpenDialog(options);
		if (result.canceled || result.filePaths.length === 0) return {
			ok: false,
			cancelled: true
		};
		const picked = result.filePaths[0];
		if (toolId === "gcc") saveToolchainConfig({
			manualGccPath: picked,
			preferredGccPath: picked
		});
		else saveToolchainConfig({ manualPythonPath: picked });
		cached = null;
		return {
			ok: true,
			path: picked,
			tools: detect(true)
		};
	});
	electron.ipcMain.handle(TOOLCHAIN_CHANNELS.setManualPath, (_event, toolId, path) => {
		if (toolId === "gcc") {
			if (path) saveToolchainConfig({
				manualGccPath: path,
				preferredGccPath: path
			});
			else saveToolchainConfig({
				manualGccPath: "",
				preferredGccPath: ""
			});
		} else saveToolchainConfig({ manualPythonPath: path });
		cached = null;
		return {
			ok: true,
			tools: detect(true)
		};
	});
	electron.ipcMain.handle(TOOLCHAIN_CHANNELS.selectCandidate, (_event, executable) => {
		saveToolchainConfig({ preferredGccPath: executable });
		cached = null;
		return {
			ok: true,
			tools: detect(true)
		};
	});
	electron.ipcMain.handle("toolchain:reset", () => {
		clearToolchainConfig();
		cached = null;
		return {
			ok: true,
			tools: detect(true)
		};
	});
}
//#endregion
//#region src/main/fileOps.ts
/** 校验一个相对路径不是空、不是绝对路径、不带 .. */
function assertRelative(relativePath, what) {
	const trimmed = relativePath.trim().replace(/\\/g, "/");
	if (!trimmed) throw new Error(`${what}的名字不能为空`);
	if (trimmed.startsWith("/") || /^[a-zA-Z]:/.test(trimmed)) throw new Error(`${what}必须是工作区内的相对路径`);
	for (const segment of trimmed.split("/")) if (segment === "..") throw new Error(`${what}不能包含 ..`);
	return trimmed;
}
/** 文件名里不允许出现的字符（Windows 规则，对初学者友好地提前拦住） */
var ILLEGAL_NAME = /[<>:"|?*\u0000-\u001f]/;
function assertSimpleName(name, what) {
	const trimmed = name.trim();
	if (!trimmed) throw new Error(`${what}的名字不能为空`);
	if (trimmed === "." || trimmed === "..") throw new Error(`${what}的名字不合法`);
	if (ILLEGAL_NAME.test(trimmed)) throw new Error(`${what}的名字不能包含 < > : " | ? * 这些字符`);
	if (/[. ]$/.test(trimmed)) throw new Error(`${what}的名字不能以点或空格结尾`);
	return trimmed;
}
async function exists(path) {
	try {
		await (0, node_fs_promises.stat)(path);
		return true;
	} catch {
		return false;
	}
}
/** 新建文件。已存在就报错，绝不静默覆盖。 */
async function createFile(root, parentRelative, name) {
	const safeName = assertSimpleName(name, "文件");
	const parent = parentRelative ? assertRelative(parentRelative, "目录") : "";
	const absolute = resolveInside(root, parent ? `${parent}/${safeName}` : safeName);
	if (await exists(absolute)) throw new Error(`「${safeName}」已经存在了，换个名字吧`);
	await (0, node_fs_promises.mkdir)((0, node_path.dirname)(absolute), { recursive: true });
	await (0, node_fs_promises.writeFile)(absolute, "", "utf8");
	return { path: parent ? `${parent}/${safeName}` : safeName };
}
/** 新建文件夹 */
async function createDirectory(root, parentRelative, name) {
	const safeName = assertSimpleName(name, "文件夹");
	const parent = parentRelative ? assertRelative(parentRelative, "目录") : "";
	const absolute = resolveInside(root, parent ? `${parent}/${safeName}` : safeName);
	if (await exists(absolute)) throw new Error(`「${safeName}」已经存在了，换个名字吧`);
	await (0, node_fs_promises.mkdir)(absolute, { recursive: true });
	return { path: parent ? `${parent}/${safeName}` : safeName };
}
/** 重命名（只改名字，不移动位置） */
async function renameEntry(root, relativePath, newName) {
	const source = assertRelative(relativePath, "条目");
	const safeName = assertSimpleName(newName, "条目");
	const absoluteSource = resolveInside(root, source);
	if (!await exists(absoluteSource)) throw new Error(`「${source}」不存在`);
	const parent = source.includes("/") ? source.slice(0, source.lastIndexOf("/")) : "";
	const target = parent ? `${parent}/${safeName}` : safeName;
	const absoluteTarget = resolveInside(root, target);
	if (absoluteTarget !== absoluteSource && await exists(absoluteTarget)) throw new Error(`「${safeName}」已经存在了，换个名字吧`);
	await (0, node_fs_promises.rename)(absoluteSource, absoluteTarget);
	return { path: target };
}
/**
* 删除文件或文件夹。
*
* 目录默认只允许删空目录：初学者误点删除就把整个项目删掉的风险太高了。
* 确实要删非空目录时，调用方必须显式传 recursive。
*/
async function deleteEntry(root, relativePath, recursive = false) {
	const target = assertRelative(relativePath, "条目");
	const absolute = resolveInside(root, target);
	if (absolute === resolveInside(root, "")) throw new Error("不能删除工作区根目录");
	let info;
	try {
		info = await (0, node_fs_promises.stat)(absolute);
	} catch {
		throw new Error(`「${target}」不存在`);
	}
	if (info.isDirectory() && !recursive) {
		const { readdir } = await import("node:fs/promises");
		const children = await readdir(absolute);
		if (children.length > 0) throw new Error(`「${target}」不是空文件夹，里面还有 ${children.length} 个条目`);
	}
	await (0, node_fs_promises.rm)(absolute, {
		recursive: info.isDirectory() || recursive,
		force: false
	});
	return { path: target };
}
//#endregion
//#region src/shared/build.ts
var BUILD_CHANNELS = {
	scan: "build:scan",
	ensureCMakeLists: "build:ensureCMakeLists",
	compile: "build:compile",
	run: "build:run",
	revealBuildDir: "build:revealBuildDir"
};
/** 编译/运行超时 */
var BUILD_TIMEOUT_MS = 18e4;
var RUN_TIMEOUT_MS = 15e3;
//#endregion
//#region src/main/build.ts
/**
* 构建系统：定位项目 → 生成 CMakeLists → 编译 → 运行。
*
* 三个关键决定：
*
* 1. **怎么知道 main 在哪**：搜 `int main(` / `WinMain(` 的实际内容，
*    而不是靠文件名猜。文件名可能是任意名字（不少 OI 选手写 `a.cpp`），
*    只有内容里出现 main 才算入口。Python 同理，认 `__main__`。
*
* 2. **生成的 CMakeLists 要能被初学者看懂**：带中文注释，
*    解释每一行在做什么，而不是丢一份模板给他。
*
* 3. **运行必须注入 PATH**：MinGW 编译出的 exe 直接运行会因缺少
*    libstdc++-6.dll 而**静默失败**（退出码 -1073741515，没有任何输出）。
*    编译成功、运行却什么都不显示，是最难查的那种问题。
*/
var SKIP_DIRECTORIES = /* @__PURE__ */ new Set([
	"node_modules",
	".git",
	".svn",
	".hg",
	"dist",
	"build",
	".sparkle-build",
	"cmake-build-debug",
	"cmake-build-release",
	"out",
	".vscode",
	".idea",
	"venv",
	".venv",
	"__pycache__",
	".cache"
]);
/** 判断一个 C++ 源文件里有没有入口函数 */
function hasCppMain(content) {
	const stripped = content.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n]*/g, " ");
	return /\b(main|wmain|WinMain|wWinMain)\s*\(/.test(stripped);
}
function isPythonEntry(content) {
	const stripped = content.replace(/#[^\n]*/g, " ");
	return /if\s+__name__\s*==\s*['"]__main__['"]/.test(stripped);
}
function isCppSource(name) {
	const lower = name.toLowerCase();
	return lower.endsWith(".cpp") || lower.endsWith(".cc") || lower.endsWith(".cxx") || lower.endsWith(".c++") || lower.endsWith(".c");
}
/**
* 在工作区里找入口文件。
* 返回按目录分组的结果，一个目录就是一个项目。
*/
async function scanProjects(root) {
	const entriesByDirectory = /* @__PURE__ */ new Map();
	let scanned = 0;
	let truncated = false;
	const queue = [{
		absolute: root,
		relative: ""
	}];
	while (queue.length > 0) {
		if (scanned >= 4e3) {
			truncated = true;
			break;
		}
		const current = queue.shift();
		scanned += 1;
		let children;
		try {
			children = await (0, node_fs_promises.readdir)(current.absolute, { withFileTypes: true });
		} catch {
			continue;
		}
		for (const child of children) {
			const absolute = (0, node_path.join)(current.absolute, child.name);
			const relative = current.relative ? `${current.relative}/${child.name}` : child.name;
			if (child.isDirectory()) {
				if (SKIP_DIRECTORIES.has(child.name) || child.name.startsWith(".")) continue;
				queue.push({
					absolute,
					relative
				});
				continue;
			}
			const cpp = isCppSource(child.name);
			const python = child.name.toLowerCase().endsWith(".py");
			if (!cpp && !python) continue;
			let content = "";
			try {
				const raw = await (0, node_fs_promises.readFile)(absolute, "utf8");
				if (raw.length <= 262144) content = raw;
			} catch {
				continue;
			}
			const nameSuggestsMain = /^main\.(cpp|cc|cxx|c|py)$/i.test(child.name);
			if (python && (isPythonEntry(content) || nameSuggestsMain)) {
				const list = entriesByDirectory.get(current.relative) ?? [];
				list.push({
					relative,
					language: "python"
				});
				entriesByDirectory.set(current.relative, list);
			} else if (cpp && (hasCppMain(content) || nameSuggestsMain)) {
				const list = entriesByDirectory.get(current.relative) ?? [];
				list.push({
					relative,
					language: "cpp"
				});
				entriesByDirectory.set(current.relative, list);
			}
		}
	}
	const projects = [];
	for (const [directory, entries] of entriesByDirectory) {
		const entry = [...entries].sort((left, right) => {
			const leftMain = /^main\./i.test((0, node_path.basename)(left.relative)) ? 0 : 1;
			const rightMain = /^main\./i.test((0, node_path.basename)(right.relative)) ? 0 : 1;
			if (leftMain !== rightMain) return leftMain - rightMain;
			return left.relative.localeCompare(right.relative);
		})[0];
		const absoluteDirectory = directory ? (0, node_path.join)(root, directory) : root;
		let sourceCount = 1;
		try {
			const names = await (0, node_fs_promises.readdir)(absoluteDirectory);
			sourceCount = Math.max(1, names.filter((name) => isCppSource(name)).length);
		} catch {
			sourceCount = 1;
		}
		projects.push({
			directory,
			entry: entry.relative,
			entryName: (0, node_path.basename)(entry.relative),
			language: entry.language,
			name: directory ? (0, node_path.basename)(directory) : (0, node_path.basename)(root) || "当前目录",
			hasCMakeLists: (0, node_fs.existsSync)((0, node_path.join)(absoluteDirectory, "CMakeLists.txt")),
			sourceCount
		});
	}
	projects.sort((left, right) => {
		if (left.hasCMakeLists !== right.hasCMakeLists) return left.hasCMakeLists ? -1 : 1;
		return left.directory.localeCompare(right.directory);
	});
	return {
		projects,
		scannedDirectories: scanned,
		truncated
	};
}
/** 生成一份带中文注释的 CMakeLists.txt */
async function ensureCMakeLists(root, project) {
	const absoluteDirectory = project.directory ? (0, node_path.join)(root, project.directory) : root;
	const cmakePath = (0, node_path.join)(absoluteDirectory, "CMakeLists.txt");
	if ((0, node_fs.existsSync)(cmakePath)) return {
		path: cmakePath,
		created: false,
		content: await (0, node_fs_promises.readFile)(cmakePath, "utf8")
	};
	const settings = await loadSettings();
	const sources = (await (0, node_fs_promises.readdir)(absoluteDirectory).catch(() => [])).filter((name) => isCppSource(name)).sort();
	const sourceList = sources.length > 0 ? sources : [(0, node_path.basename)(project.entry)];
	const projectName = (project.directory ? (0, node_path.basename)(project.directory) : "sparkle_app").replace(/[^A-Za-z0-9_]/g, "_");
	const content = [
		"# 这个文件是 Sparkle IDE 自动生成的，用来告诉 CMake 怎么编译这个项目。",
		"# 你可以随意修改它；改过之后 IDE 不会再覆盖。",
		"",
		"cmake_minimum_required(VERSION 3.10)",
		"",
		`project(${projectName || "sparkle_app"} CXX)`,
		"",
		...standardCmakeOptions(settings.cppStandard),
		"",
		"# 打开常用警告（只是提醒，不会因为警告就编译失败）",
		"if(NOT MSVC)",
		"    add_compile_options(-Wall -Wextra)",
		"endif()",
		"",
		"# 把下面这些源文件编译成一个可执行文件",
		`add_executable(${projectName || "sparkle_app"}`,
		...sourceList.map((name) => `    ${name}`),
		")",
		"",
		"# 让同目录下的自定义头文件可以直接 #include \"xxx.h\"",
		`target_include_directories(${projectName || "sparkle_app"} PRIVATE \${CMAKE_CURRENT_SOURCE_DIR})`,
		""
	].join("\n");
	await (0, node_fs_promises.writeFile)(cmakePath, content, "utf8");
	return {
		path: cmakePath,
		created: true,
		content
	};
}
/** 跑一个命令，收集输出，支持超时 */
function runCommand$1(command, args, options) {
	return new Promise((resolve) => {
		const child = (0, node_child_process.spawn)(command, args, {
			cwd: options.cwd,
			env: options.env,
			windowsHide: true,
			shell: false
		});
		let output = "";
		let timedOut = false;
		const timer = setTimeout(() => {
			timedOut = true;
			child.kill();
		}, options.timeoutMs);
		const collect = (chunk) => {
			const text = chunk.toString("utf8");
			output += text;
			options.onOutput?.(text);
		};
		child.stdout.on("data", collect);
		child.stderr.on("data", collect);
		child.on("error", (error) => {
			clearTimeout(timer);
			output += `\n${error.message}`;
			resolve({
				code: -1,
				output,
				timedOut
			});
		});
		child.on("close", (code) => {
			clearTimeout(timer);
			resolve({
				code,
				output,
				timedOut
			});
		});
	});
}
/**
* 往环境变量的 PATH 前面插一段。
*
* **这里有个 Windows 上的真实陷阱**：`process.env` 里 PATH 的实际键名可能是
* `Path` 而不是 `PATH`（取决于是谁启动的进程）。直接写 `env.PATH = ...` 会
* 造出一个重复键，两个键一起传给子进程时 Windows 取哪一个是不确定的 ——
* 实测表现就是 `spawn cmake ENOENT`：明明装了 CMake 却找不到。
* 所以要按实际存在的键名去写，并把其它大小写变体清掉。
*/
function prependPath(env, prefix) {
	const existingKey = Object.keys(env).find((name) => name.toLowerCase() === "path");
	const current = existingKey ? env[existingKey] ?? "" : "";
	for (const name of Object.keys(env)) if (name.toLowerCase() === "path") delete env[name];
	env.PATH = `${prefix};${current}`;
}
/**
* 构造编译时的环境变量。
*
* PATH 里必须加上编译器自己的 bin 目录：否则 CMake 找不到 g++，
* 而且后面运行产物时也会缺 DLL。
*/
function buildEnvironment(compiler) {
	const env = { ...process.env };
	delete env.ELECTRON_RUN_AS_NODE;
	prependPath(env, compiler.binDir);
	env.CXX = compiler.executable;
	env.CC = (0, node_path.join)(compiler.binDir, "gcc.exe");
	return env;
}
/**
* MinGW Makefiles 在**路径含非 ASCII 字符**时会生成坏掉的 Makefile。
*
* 这是实测结论（逐个字符做过对照实验）：
*   纯 ASCII / 空格 / 单引号 / 半角 !  → 编译成功
*   纯中文 / 全角括号 / 全角感叹号      → configure 成功但 make 报
*                                        "No rule to make target"
*
* 中文用户的路径里带中文太常见了（本机工作区就是
* ".../不要删！！！！hmh's temporary folder/..."），所以必须处理：
* 把项目复制到一个纯 ASCII 的临时目录去构建，完了把产物拷回来。
*/
function needsAsciiStaging(directory) {
	return /[^\x00-\x7F]/.test(directory);
}
/** 把项目复制到纯 ASCII 的临时目录，返回该目录 */
function stageProject(sourceDir) {
	const hash = (0, node_crypto.createHash)("sha1").update(sourceDir).digest("hex").slice(0, 12);
	const target = (0, node_path.join)((0, node_os.tmpdir)(), `sparkle-build-${hash}`);
	(0, node_fs.rmSync)(target, {
		recursive: true,
		force: true
	});
	(0, node_fs.mkdirSync)(target, { recursive: true });
	(0, node_fs.cpSync)(sourceDir, target, {
		recursive: true,
		filter: (source) => {
			const name = (0, node_path.basename)(source);
			if (SKIP_DIRECTORIES.has(name)) return false;
			return !name.endsWith(".exe") && !name.endsWith(".obj");
		}
	});
	return target;
}
/** 把编译器的原始报错翻译成初学者能懂的一句话 */
function friendlyBuildError(output) {
	if (/undefined reference to [`'"]?WinMain/i.test(output)) return "链接器在找 Windows 图形程序的入口 WinMain，但你的代码里只有 main。\n说明这次被当成「图形界面程序」去链接了，常见原因是：\n  · CMakeLists.txt 里 add_executable 带了 WIN32 关键字（把 WIN32 删掉即可）\n  · 编译选项里带了 -mwindows（去掉它）\n如果你确实想写图形界面程序，那才需要把 main 改成 WinMain。";
	if (/undefined reference to [`'"]?main/i.test(output)) return "链接器找不到程序的入口 main。检查一下：\n  · 是不是把 main 拼错了（比如 mian）\n  · 是不是写成了 WinMain —— 那是图形界面程序的入口，控制台程序要用 int main()";
	if (/cannot find -l|undefined reference to/i.test(output)) return "链接失败：用到了没有定义的函数。检查函数名有没有拼错，或者是不是忘了写函数体。";
	if (/stray '\\\d+' in program/i.test(output)) return "某一行的名字里有中文（或其它非 ASCII 字符），而这个编译器版本不支持。\n把变量名、函数名换成英文就好了（例如 计数 → count）。\n或者到「工具链」面板换一个更新的编译器（GCC 5 以上支持中文标识符）。";
	if (/fatal error:.*No such file|No such file or directory/i.test(output) && /include/i.test(output)) return "找不到头文件：检查 #include 的文件名拼写，以及那个文件是不是也在项目目录里。";
	if (/expected .* before|expected .* at end of input/i.test(output)) return "语法错误：某一行的括号、分号或花括号可能没有配对。看第一条错误的位置最准。";
	if (/was not declared in this scope/i.test(output)) return "用到了没有声明的名字：可能是变量名拼错了，或者忘了先定义再用。";
	if (/CMake Error/i.test(output)) return "CMake 配置失败，通常是 CMakeLists.txt 里的路径或文件名写错了。";
	if (/Permission denied|being used by another process/i.test(output)) return "文件被占用了：上一次编译出来的程序可能还在运行，把它关掉再试。";
	return "";
}
/** 编译一个项目。cmakeExecutable 由调用方给出（工具链探测已经找到它的绝对路径）。 */
async function compileProject(root, compiler, request, cmakeExecutable = "cmake") {
	const startedAt = Date.now();
	if (request.language === "python") return {
		ok: true,
		output: "Python 不需要编译，直接运行即可。",
		durationMs: 0
	};
	if (!compiler.hasMake) return {
		ok: false,
		output: "",
		durationMs: 0,
		friendlyError: "这个编译器目录里没有 mingw32-make，CMake 没法生成 Makefile。到「工具链」面板换一个编译器。"
	};
	/**
	* MinGW 的 g++ 会**基于自身安装路径**去推算运行时库的位置
	* （crt2.o、crtbegin.o、libstdc++、libmingw32、libgcc_s …），
	* 而它处理不了路径里的非 ASCII 字符。
	*
	* 实测对照（同一份 GCC 12.2）：
	*   I:\sparkle-bundled\mingw64            → 编译成功
	*   I:\...\.bundled-toolchain\...         → 编译成功（含空格也没问题）
	*   I:\...\7. 【推荐】预装编译器 开箱即用\... → 失败，报 cannot find crt2.o / -lstdc++
	*
	* 报错看起来像"文件缺失"，很容易被误判成包不完整。
	* 这里提前拦下来，直接告诉用户是文件夹名字的问题 —— 他改个名字就好了。
	*/
	if (/[^\x00-\x7F]/.test(compiler.binDir)) return {
		ok: false,
		output: "",
		durationMs: 0,
		friendlyError: `编译器的安装路径里有中文或其它非 ASCII 字符：\n  ${compiler.binDir}\n\nMinGW 的 g++ 处理不了这种路径，会报「找不到 crt2.o」「找不到 -lstdc++」这类
看起来像文件缺失的错误，其实只是路径的问题。

解决办法：把 Sparkle IDE 所在的文件夹改成一个纯英文的名字（例如 SparkleIDE），
然后重新打开它。项目本身的路径可以随便用中文，我们有别的办法处理。`
	};
	const absoluteDirectory = request.directory ? (0, node_path.join)(root, request.directory) : root;
	await ensureCMakeLists(root, {
		directory: request.directory,
		entry: request.entry
	});
	const staged = needsAsciiStaging(absoluteDirectory);
	const buildRoot = staged ? stageProject(absoluteDirectory) : absoluteDirectory;
	const buildDir = (0, node_path.join)(buildRoot, ".sparkle-build");
	await (0, node_fs_promises.mkdir)(buildDir, { recursive: true });
	const env = buildEnvironment(compiler);
	const notes = [];
	if (staged) notes.push(`注意：你的项目路径里有中文或全角符号，MinGW 的 make 处理不了，
所以这次是在临时目录里编译的：${buildRoot}\n编译产物会复制回项目的 .sparkle-build 目录，你不需要做别的。
`);
	const extraFlags = [];
	if (request.optimize !== "none") extraFlags.push(`-${request.optimize}`);
	if (request.staticLink) extraFlags.push("-static");
	if (!(0, node_fs.existsSync)((0, node_path.join)(buildDir, "CMakeCache.txt"))) {
		const configure = await runCommand$1(cmakeExecutable, [
			"-S",
			buildRoot,
			"-B",
			buildDir,
			"-G",
			"MinGW Makefiles",
			`-DCMAKE_CXX_COMPILER=${compiler.executable}`,
			`-DCMAKE_MAKE_PROGRAM=${compiler.makeExecutable}`,
			`-DCMAKE_BUILD_TYPE=${request.optimize === "none" ? "Debug" : "Release"}`,
			`-DCMAKE_CXX_FLAGS=${extraFlags.join(" ")}`
		], {
			cwd: buildRoot,
			env,
			timeoutMs: BUILD_TIMEOUT_MS
		});
		if (configure.code !== 0) return {
			ok: false,
			output: notes.join("") + configure.output,
			durationMs: Date.now() - startedAt,
			friendlyError: friendlyBuildError(configure.output) || "CMake 配置失败。"
		};
	}
	const build = await runCommand$1(cmakeExecutable, [
		"--build",
		buildDir,
		"--parallel"
	], {
		cwd: buildRoot,
		env,
		timeoutMs: BUILD_TIMEOUT_MS
	});
	const durationMs = Date.now() - startedAt;
	if (build.timedOut) return {
		ok: false,
		output: notes.join("") + build.output,
		durationMs,
		friendlyError: "编译超时了，代码里是不是有特别大的数组或模板展开？"
	};
	if (build.code !== 0) return {
		ok: false,
		output: notes.join("") + build.output,
		durationMs,
		friendlyError: friendlyBuildError(build.output) || "编译失败，请看上面的错误信息。"
	};
	const exeName = (await (0, node_fs_promises.readdir)(buildDir).catch(() => [])).find((name) => name.toLowerCase().endsWith(".exe"));
	if (!exeName) return {
		ok: true,
		output: notes.join("") + build.output,
		durationMs,
		friendlyError: "编译通过了，但没找到可执行文件，检查一下 CMakeLists 里的 add_executable。"
	};
	let executable = (0, node_path.join)(buildDir, exeName);
	if (staged) {
		const finalDir = (0, node_path.join)(absoluteDirectory, ".sparkle-build");
		(0, node_fs.mkdirSync)(finalDir, { recursive: true });
		const finalPath = (0, node_path.join)(finalDir, exeName);
		(0, node_fs.cpSync)(executable, finalPath);
		executable = finalPath;
	}
	return {
		ok: true,
		output: notes.join("") + build.output,
		durationMs,
		executable
	};
}
/** 运行编译产物，或者直接运行 Python 脚本 */
async function runProject(root, compiler, request, executable, pythonExecutable) {
	const startedAt = Date.now();
	const absoluteDirectory = request.directory ? (0, node_path.join)(root, request.directory) : root;
	let command;
	let args;
	if (request.language === "python") {
		command = pythonExecutable || "python";
		args = [(0, node_path.join)(root, request.entry)];
	} else {
		if (!executable) return {
			exitCode: null,
			output: "还没有编译出可执行文件，先点「一键编译」。",
			durationMs: 0,
			timedOut: false
		};
		command = executable;
		args = [];
	}
	const env = { ...process.env };
	delete env.ELECTRON_RUN_AS_NODE;
	if (request.language === "cpp" && compiler) prependPath(env, compiler.binDir);
	if (request.language === "python") {
		env.PYTHONUTF8 = "1";
		env.PYTHONIOENCODING = "utf-8";
	}
	const result = await runCommand$1(command, args, {
		cwd: absoluteDirectory,
		env,
		timeoutMs: RUN_TIMEOUT_MS
	});
	return {
		exitCode: result.code,
		output: result.output,
		durationMs: Date.now() - startedAt,
		timedOut: result.timedOut
	};
}
//#endregion
//#region src/shared/search.ts
var SEARCH_CHANNELS = { query: "search:query" };
/** 这些目录永远不搜 */
var DEFAULT_EXCLUDED_DIRECTORIES = [
	"node_modules",
	".git",
	".svn",
	".hg",
	"dist",
	"out",
	"build",
	".sparkle-build",
	"__pycache__",
	".cache",
	"venv",
	".venv"
];
//#endregion
//#region src/main/search.ts
/**
* 工作区搜索。
*
* 关键点：**分片让出事件循环**。
* 同步遍历几万个文件会把主进程冻住，界面直接卡死 —— 而搜索恰恰是最容易
* 触发这种情况的操作（用户输入一个常见词，命中的文件可能非常多）。
* 所以每处理一批文件就 await 一次 setImmediate，让 IPC 与界面事件有机会跑。
*/
/** 只搜这些扩展名，避免去读图片、压缩包这类二进制文件 */
var TEXT_EXTENSIONS = /* @__PURE__ */ new Set([
	".c",
	".cc",
	".cpp",
	".cxx",
	".h",
	".hh",
	".hpp",
	".hxx",
	".py",
	".pyw",
	".js",
	".mjs",
	".cjs",
	".ts",
	".tsx",
	".jsx",
	".vue",
	".json",
	".md",
	".txt",
	".yml",
	".yaml",
	".toml",
	".ini",
	".cfg",
	".conf",
	".html",
	".htm",
	".css",
	".scss",
	".less",
	".xml",
	".csv",
	".log",
	".sh",
	".bat",
	".cmd",
	".ps1",
	".make",
	".cmake",
	".gitignore"
]);
var SPECIAL_TEXT_NAMES = /* @__PURE__ */ new Set([
	"CMakeLists.txt",
	"Makefile",
	"makefile",
	".gitignore",
	"README",
	"LICENSE"
]);
function looksTextual(name) {
	if (SPECIAL_TEXT_NAMES.has(name)) return true;
	const dot = name.lastIndexOf(".");
	if (dot === -1) return false;
	return TEXT_EXTENSIONS.has(name.slice(dot).toLowerCase());
}
/** 单文件超过这个大小就不搜了（可能是个日志文件） */
var MAX_SEARCH_FILE_BYTES = 2097152;
function buildMatcher(options) {
	const { query, caseSensitive, regex } = options;
	if (regex) try {
		const expression = new RegExp(query, caseSensitive ? "g" : "gi");
		return { test: (line) => {
			expression.lastIndex = 0;
			const match = expression.exec(line);
			return match ? {
				start: match.index,
				length: match[0].length
			} : null;
		} };
	} catch (error) {
		return {
			test: () => null,
			error: `正则表达式写错了：${error instanceof Error ? error.message : String(error)}`
		};
	}
	const needle = caseSensitive ? query : query.toLowerCase();
	return { test: (line) => {
		const index = (caseSensitive ? line : line.toLowerCase()).indexOf(needle);
		return index === -1 ? null : {
			start: index,
			length: query.length
		};
	} };
}
function toPreview(line) {
	const trimmed = line.trim();
	return trimmed.length > 200 ? `${trimmed.slice(0, 200)}…` : trimmed;
}
/** 每处理这么多文件让出一次事件循环 */
var YIELD_EVERY = 60;
async function searchWorkspace(root, options) {
	const startedAt = Date.now();
	const query = options.query ?? "";
	if (query.length === 0) return {
		matches: [],
		truncated: false,
		scannedFiles: 0,
		elapsedMs: 0
	};
	const maxResults = options.maxResults ?? 300;
	const excluded = /* @__PURE__ */ new Set([...DEFAULT_EXCLUDED_DIRECTORIES, ...options.excludeDirectories ?? []]);
	const matcher = buildMatcher(options);
	if (matcher.error) return {
		matches: [],
		truncated: false,
		scannedFiles: 0,
		elapsedMs: 0,
		error: matcher.error
	};
	const nameNeedle = options.caseSensitive ? query : query.toLowerCase();
	const matches = [];
	let scannedFiles = 0;
	let truncated = false;
	let sinceYield = 0;
	const queue = [{
		absolute: root,
		relative: ""
	}];
	while (queue.length > 0) {
		if (matches.length >= maxResults || scannedFiles >= 2e4) {
			truncated = true;
			break;
		}
		const current = queue.shift();
		let children;
		try {
			children = await (0, node_fs_promises.readdir)(current.absolute, { withFileTypes: true });
		} catch {
			continue;
		}
		for (const child of children) {
			const absolute = (0, node_path.join)(current.absolute, child.name);
			const relative = current.relative ? `${current.relative}/${child.name}` : child.name;
			if (child.isDirectory()) {
				if (excluded.has(child.name) || child.name.startsWith(".")) continue;
				queue.push({
					absolute,
					relative
				});
				continue;
			}
			if (matches.length >= maxResults || scannedFiles >= 2e4) {
				truncated = true;
				break;
			}
			if (options.mode === "filename") {
				const index = (options.caseSensitive ? child.name : child.name.toLowerCase()).indexOf(nameNeedle);
				if (index !== -1) matches.push({
					path: relative,
					line: 0,
					column: 0,
					preview: relative,
					matchStart: relative.length - child.name.length + index,
					matchLength: query.length
				});
				continue;
			}
			if (!looksTextual(child.name)) continue;
			try {
				if ((await (0, node_fs_promises.stat)(absolute)).size > MAX_SEARCH_FILE_BYTES) continue;
			} catch {
				continue;
			}
			scannedFiles += 1;
			let content;
			try {
				content = await (0, node_fs_promises.readFile)(absolute, "utf8");
			} catch {
				continue;
			}
			const lines = content.split("\n");
			for (let index = 0; index < lines.length; index += 1) {
				if (matches.length >= maxResults) {
					truncated = true;
					break;
				}
				const line = lines[index];
				const hit = matcher.test(line);
				if (!hit) continue;
				matches.push({
					path: relative,
					line: index + 1,
					column: hit.start + 1,
					preview: toPreview(line),
					matchStart: hit.start,
					matchLength: hit.length
				});
			}
			sinceYield += 1;
			if (sinceYield >= YIELD_EVERY) {
				sinceYield = 0;
				await new Promise((resolve) => setImmediate(resolve));
			}
		}
	}
	return {
		matches,
		truncated,
		scannedFiles,
		elapsedMs: Date.now() - startedAt
	};
}
//#endregion
//#region src/shared/ide.ts
var IDE_CHANNELS = {
	compileFile: "ide:compileFile",
	runFile: "ide:runFile",
	/** 在真正的控制台窗口里打开程序（能接收键盘输入、结束时停住等回车） */
	runInConsole: "ide:runInConsole",
	/** 打开单个文件（系统对话框，可以在工作区之外） */
	openFileDialog: "ide:openFileDialog",
	debugStart: "ide:debugStart",
	debugCommand: "ide:debugCommand",
	debugStop: "ide:debugStop",
	debugEvent: "ide:debugEvent"
};
/** 单文件编译的超时 */
var SINGLE_BUILD_TIMEOUT_MS = 6e4;
/** 被调试程序的运行上限，防止死循环挂住 */
var DEBUG_RUN_TIMEOUT_MS = 12e4;
//#endregion
//#region src/main/singleFile.ts
/**
* 单文件编译与运行 —— 刻意绕开 CMake。
*
* 场景：OI 选手写了个 `a.cpp`，一节课的作业只有一个 `main.cpp`。
* 为这种文件走一遍 CMake 的 configure + make 既慢又苛刻
* （得有 CMakeLists、路径不能有非 ASCII、还得有 make）。
* 直接调 g++ 一条命令就完事，这就是所有 IDE 都有的"编译当前文件"。
*/
/** 这些扩展名走 C++ 编译 */
var CPP_EXTENSIONS = /* @__PURE__ */ new Set([
	".cpp",
	".cc",
	".cxx",
	".c++",
	".c"
]);
function isCompilableFile(path) {
	return CPP_EXTENSIONS.has((0, node_path.extname)(path).toLowerCase());
}
function runCommand(command, args, options) {
	return new Promise((resolve) => {
		const child = (0, node_child_process.spawn)(command, args, {
			cwd: options.cwd,
			env: options.env,
			windowsHide: true,
			shell: false
		});
		let output = "";
		let timedOut = false;
		const timer = setTimeout(() => {
			timedOut = true;
			child.kill();
		}, options.timeoutMs);
		const collect = (chunk) => {
			output += chunk.toString("utf8");
		};
		child.stdout.on("data", collect);
		child.stderr.on("data", collect);
		child.on("error", (error) => {
			clearTimeout(timer);
			resolve({
				code: -1,
				output: `${output}\n${error.message}`,
				timedOut
			});
		});
		child.on("close", (code) => {
			clearTimeout(timer);
			resolve({
				code,
				output,
				timedOut
			});
		});
	});
}
/**
* 按编译器版本挑 C++ 标准。
*
* **实测出来的必要修正**：本机 Dev-Cpp 自带的 TDM64 是 GCC 4.9.2，
* 而 GCC 5 才支持 -std=c++17 —— 硬写 c++17 会直接报
* "unrecognized command line option '-std=c++17'"，编译必然失败。
* 如果用户机器上只有这一个编译器，那就是"怎么点都编译不了"。
*/
/** 用户可以在「设置」里指定的 C++ 标准。c++26 需要 GCC 15+，指定了但编译器
* 不支持时不会让编译直接失败，而是沿阶梯降到编译器真正支持的最高标准。 */
var SUPPORTED_STANDARDS = ["c++11", "c++14", "c++17", "c++20", "c++23", "c++26"];
/** 编译器主版本 → 按年代映射到的标准（GCC 15 起才有 -std=c++26） */
function ladderStandard(major) {
	if (major >= 15) return "c++26";
	if (major >= 14) return "c++23";
	if (major >= 11) return "c++20";
	if (major >= 5) return "c++17";
	if (major >= 4) return "c++14";
	return "c++11";
}
/**
* 探针：这个编译器到底支不支持某个 -std= 选项。
*
* 不猜版本号，而是真的拿空源文件去问编译器（预处理阶段即可，不生成任何文件）。
* 结果是「这个可执行文件 + 这个标准」粒度的，同一次会话内只问一次。
*/
var standardProbeCache = /* @__PURE__ */ new Map();
function compilerSupportsStandard(executable, standard) {
	if (!executable) return false;
	const key = `${executable}|${standard}`;
	const cached = standardProbeCache.get(key);
	if (cached !== void 0) return cached;
	let supported = false;
	try {
		const result = (0, node_child_process.spawnSync)(executable, [`-std=${standard}`, "-E", "-x", "c++", "-"], {
			encoding: "utf8",
			input: "",
			timeout: 1e4,
			windowsHide: true
		});
		const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
		const failed = result.status !== 0 || result.error || /unrecognized command line option|is not valid|not supported|error:/i.test(output);
		supported = !failed;
	} catch {
		supported = false;
	}
	standardProbeCache.set(key, supported);
	return supported;
}
/**
* 挑编译标准。
*
* 优先级：用户在「设置」里指定的 > 按编译器版本自动。
* 指定的标准编译器不支持时，沿阶梯往下找第一个支持的（例如指定 C++26
* 但机器上只有 GCC 12，就用 C++20），而不是让编译直接失败。
*/
function standardFlag(version, requested, executable) {
	const major = Number.parseInt((version || "0").split(".")[0] ?? "0", 10) || 0;
	const auto = ladderStandard(major);
	const wanted = requested && SUPPORTED_STANDARDS.includes(requested) ? requested : auto;
	if (!executable) return `-std=${wanted}`;
	if (compilerSupportsStandard(executable, wanted)) return `-std=${wanted}`;
	for (let index = SUPPORTED_STANDARDS.indexOf(wanted) - 1; index >= 0; index -= 1) {
		if (compilerSupportsStandard(executable, SUPPORTED_STANDARDS[index])) return `-std=${SUPPORTED_STANDARDS[index]}`;
	}
	return `-std=${auto}`;
}
/**
* 生成 CMakeLists 里的「按编译器版本挑 C++ 标准」片段，与 standardFlag 同一套阶梯。
* 用户在「设置」里指定了标准就听用户的。
*/
function standardCmakeOptions(requested) {
	const wanted = requested && SUPPORTED_STANDARDS.includes(requested) ? requested : "";
	if (wanted) return [
		"# 按编译器版本挑 C++ 标准。",
		`# 这里用的是「设置」里指定的 ${wanted}。`,
		`add_compile_options(-std=${wanted})`
	];
	return [
		"# 按编译器版本挑 C++ 标准。",
		"# GCC 15 起才支持 C++26，14 起支持 C++23，11 起支持 C++20，",
		"# 5 起才支持 C++17；Dev-Cpp 自带的 GCC 4.9 只到 C++14，",
		"# 硬写更高的会直接报 \"unrecognized command line option\"。",
		"if(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 15)",
		"    add_compile_options(-std=c++26)",
		"elseif(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 14)",
		"    add_compile_options(-std=c++23)",
		"elseif(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 11)",
		"    add_compile_options(-std=c++20)",
		"elseif(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 5)",
		"    add_compile_options(-std=c++17)",
		"elseif(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 4)",
		"    add_compile_options(-std=c++14)",
		"else()",
		"    add_compile_options(-std=c++11)",
		"endif()"
	];
}
/** 编译器的输出说明它不认识我们给的 -std= 选项 */
function standardUnsupported(output) {
	return /unrecognized command line option ['"]?-std=/.test(output) || /invalid argument ['"]?-std=/.test(output);
}
/** 从 g++ 的输出里挑出初学者能看懂的一句话 */
function explain(output) {
	if (/undefined reference to [`'"]?WinMain/i.test(output)) return "链接器在找 Windows 图形程序的入口 WinMain，但你的代码里只有 main。\n说明这次被当成「图形界面程序」去链接了，常见原因是：\n  · CMakeLists.txt 里 add_executable 带了 WIN32 关键字（把 WIN32 删掉即可）\n  · 编译选项里带了 -mwindows（去掉它）\n如果你确实想写图形界面程序，那才需要把 main 改成 WinMain。";
	if (/undefined reference to [`'"]?main/i.test(output)) return "链接器找不到程序的入口 main。检查一下：\n  · 是不是把 main 拼错了（比如 mian）\n  · 是不是写成了 WinMain —— 那是图形界面程序的入口，控制台程序要用 int main()";
	if (/cannot find -l|undefined reference to/i.test(output)) return "链接失败：用到了没有定义的函数。检查函数名有没有拼错，或者是不是忘了写函数体。";
	if (/stray '\\\d+' in program/i.test(output)) return "某一行的名字里有中文（或其它非 ASCII 字符），而这个编译器版本不支持。\n把变量名、函数名换成英文就好了（例如 计数 → count）。\n或者到「工具链」面板换一个更新的编译器（GCC 5 以上支持中文标识符）。";
	if (/fatal error:.*No such file|No such file or directory/i.test(output)) return "找不到头文件：检查 #include 的文件名拼写，以及那个文件是不是在同一个目录里。";
	if (/expected .* before|expected .* at end of input/i.test(output)) return "语法错误：某一行的括号、分号或花括号可能没有配对。看第一条错误的位置最准。";
	if (/was not declared in this scope/i.test(output)) return "用到了没有声明的名字：可能是变量名拼错了，或者忘了先定义再用。";
	if (/Permission denied|being used by another process/i.test(output)) return "文件被占用了：上一次跑起来的程序可能还在运行，把它关掉再试。";
	return "";
}
/**
* 编译单个源文件。
*
* 产物统一放在 `<项目目录>/.sparkle-build/single/` 下，和项目构建的产物分开放，
* 免得互相覆盖。
*/
async function compileSingleFile(root, compiler, request) {
	const startedAt = Date.now();
	if (!compiler) return {
		ok: false,
		output: "",
		durationMs: 0,
		friendlyError: "没有找到 C++ 编译器。到「工具链」面板里选一个，或者点一键下载。"
	};
	if (/[^\x00-\x7F]/.test(compiler.binDir)) return {
		ok: false,
		output: "",
		durationMs: 0,
		friendlyError: `编译器的安装路径里有中文或其它非 ASCII 字符：\n  ${compiler.binDir}\n\nMinGW 的 g++ 处理不了这种路径（会报找不到 crt2.o 这类看似缺文件的错误）。
把 Sparkle IDE 所在的文件夹改成纯英文名字再试。`
	};
	const absoluteSource = (0, node_path.join)(root, request.path);
	if (!(0, node_fs.existsSync)(absoluteSource)) return {
		ok: false,
		output: "",
		durationMs: 0,
		friendlyError: `找不到文件：${request.path}`
	};
	if (!isCompilableFile(request.path)) return {
		ok: false,
		output: "",
		durationMs: 0,
		friendlyError: `${(0, node_path.basename)(request.path)} 不是 C/C++ 源文件，不能编译。`
	};
	const sourceDirectory = (0, node_path.dirname)(absoluteSource);
	const executable = (0, node_path.join)(sourceDirectory, `${(0, node_path.basename)(request.path, (0, node_path.extname)(request.path))}.exe`);
	const env = { ...process.env };
	delete env.ELECTRON_RUN_AS_NODE;
	prependPath(env, compiler.binDir);
	const settings = await loadSettings();
	const flags = [standardFlag(compiler.version, settings.cppStandard, compiler.executable)];
	if (request.debug) flags.push("-g", "-O0");
	else flags.push(request.optimize === "none" ? "-O0" : `-${request.optimize}`);
	if (request.staticLink) flags.push("-static");
	const runCompile = (withFlags) => runCommand(compiler.executable, [
		...withFlags,
		absoluteSource,
		"-o",
		executable
	], {
		cwd: sourceDirectory,
		env,
		timeoutMs: SINGLE_BUILD_TIMEOUT_MS
	});
	let result = await runCompile(flags);
	if (result.code !== 0 && standardUnsupported(result.output)) {
		const retried = await runCompile(flags.map((flag) => flag.startsWith("-std=") ? "-std=c++14" : flag));
		if (retried.code === 0) result = retried;
		else result = await runCompile(flags.map((flag) => flag.startsWith("-std=") ? "-std=c++11" : flag));
	}
	const durationMs = Date.now() - startedAt;
	if (result.timedOut) return {
		ok: false,
		output: result.output,
		durationMs,
		friendlyError: "编译超时了，代码里是不是有特别大的数组或模板展开？"
	};
	if (result.code !== 0) return {
		ok: false,
		output: result.output,
		durationMs,
		friendlyError: explain(result.output) || "编译失败，请看上面的错误信息。"
	};
	return {
		ok: true,
		output: result.output,
		durationMs,
		executable
	};
}
/**
* 在一个**真正的控制台窗口**里打开程序，并在结束时停住等回车。
*
* 这里的实现方式是被三次实测逼出来的，值得说明为什么是现在这样：
*
* ❌ 最初的写法：`start "" cmd.exe /c "chcp & "exe" & echo. & pause"`
*    两个问题：
*    1. Node 会把参数里的引号转义成 \"，cmd 就把带引号的整串当命令名去找，
*       报「'"C:\...\T3.exe"' 不是内部或外部命令」
*    2. 加上 windowsVerbatimArguments 之后引号好了，但 **`&` 被外层 cmd 切分**：
*       `start "" cmd.exe /c chcp 65001>nul` 在新窗口里跑完就退出，
*       后面的 `exe & echo & pause` 全落在外层那个用户看不见的 cmd 里。
*       表现为「窗口打开后什么都不干，只是等着你按键，按完就关」——
*       程序其实跑了，只是跑在了错误的进程里。
*       （这一条尤其阴：用"程序有没有被执行"去验证会通过，
*         因为程序确实执行了，只是不在用户看到的那个窗口。）
*
* ✅ 现在的写法：写一个**纯 ASCII 的 .bat**，把 exe 路径通过**环境变量**传给批处理。
*    · 批处理内容全是 ASCII → 不会有中文路径在 cmd 的 OEM 代码页里被搞坏
*    · 路径走环境变量（Node 以 Unicode 传递）→ 中文路径也安全
*    · 只 spawn 一个 cmd 直接跑这个 bat，不再有 `start` 与 `&` 的嵌套切分问题
*    · `detached: true` + `stdio: 'ignore'` 会让 Windows 给这个 cmd 一个新控制台窗口
*
* 为什么不往源码里塞 cin.get()：那会改动用户的代码。交作业、对拍、自动评测时
* 多出来的 cin.get() 会让程序卡住等输入直接超时。所以停住只发生在这个窗口。
*/
function runInConsole(root, compiler, executable, language, pythonExecutable) {
	const absolute = language === "python" ? (0, node_path.join)(root, executable) : executable;
	if (!(0, node_fs.existsSync)(absolute)) return {
		ok: false,
		message: `找不到可执行文件：${absolute}`
	};
	const env = { ...process.env };
	delete env.ELECTRON_RUN_AS_NODE;
	if (language === "cpp" && compiler) prependPath(env, compiler.binDir);
	env.SPARKLE_RUN_CMD = language === "python" ? `"${pythonExecutable || "python"}" "${absolute}"` : `"${absolute}"`;
	env.SPARKLE_RUN_MSG = "程序已结束，按任意键关闭窗口";
	const batContent = [
		"@echo off",
		"chcp 65001>nul",
		"%SPARKLE_RUN_CMD%",
		"echo.",
		"echo %SPARKLE_RUN_MSG%",
		"pause >nul",
		""
	].join("\r\n");
	const batPath = (0, node_path.join)((0, node_os.tmpdir)(), `sparkle-run-${Date.now()}.bat`);
	try {
		(0, node_fs.writeFileSync)(batPath, batContent, "ascii");
	} catch (error) {
		return {
			ok: false,
			message: `准备运行脚本失败：${error instanceof Error ? error.message : String(error)}`
		};
	}
	try {
		(0, node_child_process.spawn)("cmd.exe", [
			"/c",
			"start",
			"",
			"cmd.exe",
			"/c",
			`"${batPath}"`
		], {
			cwd: (0, node_path.dirname)(absolute),
			env,
			windowsHide: false,
			detached: true,
			stdio: "ignore",
			windowsVerbatimArguments: true
		}).unref();
		return {
			ok: true,
			message: "已在新的控制台窗口里打开（结束后会停住等回车）"
		};
	} catch (error) {
		return {
			ok: false,
			message: `打开控制台失败：${error instanceof Error ? error.message : String(error)}`
		};
	}
}
/** 运行一个可执行文件（或 Python 脚本），输出回显在面板里 */
async function runExecutable(root, compiler, pythonExecutable, request) {
	const startedAt = Date.now();
	const directory = request.directory ? (0, node_path.join)(root, request.directory) : root;
	const env = { ...process.env };
	delete env.ELECTRON_RUN_AS_NODE;
	let command;
	let args;
	if (request.language === "python") {
		command = pythonExecutable || "python";
		args = [(0, node_path.join)(root, request.executable)];
		env.PYTHONUTF8 = "1";
		env.PYTHONIOENCODING = "utf-8";
	} else {
		if (!(0, node_fs.existsSync)(request.executable)) return {
			exitCode: null,
			output: "还没有编译出可执行文件，先点「编译当前文件」。",
			durationMs: 0,
			timedOut: false
		};
		command = request.executable;
		args = [];
		if (compiler) prependPath(env, compiler.binDir);
	}
	const result = await runCommand(command, args, {
		cwd: directory,
		env,
		timeoutMs: 2e4
	});
	return {
		exitCode: result.code,
		output: result.output,
		durationMs: Date.now() - startedAt,
		timedOut: result.timedOut
	};
}
//#endregion
//#region src/main/debugger.ts
/**
* 解析一个 MI 值：字符串 / 元组 / 列表。
* 返回 [值, 新的下标]。
*/
function parseValue(text, start) {
	let index = start;
	if (text[index] === "\"") {
		index += 1;
		const bytes = [];
		while (index < text.length) {
			const char = text[index];
			if (char === "\\") {
				const next = text[index + 1] ?? "";
				if (next >= "0" && next <= "7") {
					let octal = "";
					let cursor = index + 1;
					while (cursor < text.length && octal.length < 3) {
						const digit = text[cursor];
						if (digit < "0" || digit > "7") break;
						octal += digit;
						cursor += 1;
					}
					bytes.push(Number.parseInt(octal, 8));
					index = cursor;
					continue;
				}
				if (next === "n") bytes.push(10);
				else if (next === "t") bytes.push(9);
				else if (next === "r") bytes.push(13);
				else for (const byte of Buffer.from(next, "utf8")) bytes.push(byte);
				index += 2;
				continue;
			}
			if (char === "\"") {
				index += 1;
				break;
			}
			for (const byte of Buffer.from(char, "utf8")) bytes.push(byte);
			index += 1;
		}
		return [Buffer.from(bytes).toString("utf8"), index];
	}
	if (text[index] === "{") {
		index += 1;
		const tuple = {};
		while (index < text.length && text[index] !== "}") {
			const equalAt = text.indexOf("=", index);
			if (equalAt === -1) break;
			const key = text.slice(index, equalAt);
			const [value, next] = parseValue(text, equalAt + 1);
			tuple[key] = value;
			index = next;
			if (text[index] === ",") index += 1;
		}
		return [tuple, index + 1];
	}
	if (text[index] === "[") {
		index += 1;
		const list = [];
		while (index < text.length && text[index] !== "]") {
			const [value, next] = parseValue(text, index);
			list.push(value);
			index = next;
			if (text[index] === ",") index += 1;
		}
		return [list, index + 1];
	}
	let end = index;
	while (end < text.length && !",}]".includes(text[end])) end += 1;
	return [text.slice(index, end), end];
}
/**
* 剥掉 MI 记录开头的结果类名。
*
* MI 的记录形如：
*   *stopped,reason="breakpoint-hit",frame={...}
*   ^done,variables=[{name="i",value="0"}]
*   =breakpoint-created,bkpt={...}
* 开头的 stopped / done / breakpoint-created 都不带等号。
* 直接丢给 parseRecord 的话，第一个 key 会变成 "stopped,reason" 这种鬼东西 ——
* 实测后果是 reason 永远解析不出来，于是程序退出事件与局部变量全都读不到，
* 而表面上一切正常（不报错、也不崩）。
*/
function splitResultClass(body) {
	const commaAt = body.indexOf(",");
	if (commaAt === -1) return {
		resultClass: body,
		rest: ""
	};
	return {
		resultClass: body.slice(0, commaAt),
		rest: body.slice(commaAt + 1)
	};
}
/** 解析一行 MI 输出里的键值对列表（要先剥掉结果类名） */
function parseRecord(body) {
	const result = {};
	let index = 0;
	while (index < body.length) {
		const equalAt = body.indexOf("=", index);
		if (equalAt === -1) break;
		const key = body.slice(index, equalAt);
		const [value, next] = parseValue(body, equalAt + 1);
		result[key] = value;
		index = next;
		if (body[index] === ",") index += 1;
	}
	return result;
}
function asTuple(value) {
	return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}
function asString(value) {
	return typeof value === "string" ? value : "";
}
var DebugSession = class {
	options;
	child = null;
	buffer = "";
	exited = false;
	timer = null;
	/**
	* 最近一次暂停的位置。
	*
	* gdb 把"停在哪"（*stopped）和"变量是什么"（^done 的 variables）分两条消息发回来。
	* 变量事件如果不带位置，渲染层就只看到一条"暂停了但不知道停在哪"的消息，
	* 变量与位置因此对不上。所以这里记住位置，变量到达时一并带上。
	*/
	lastLocation;
	constructor(options) {
		this.options = options;
	}
	start() {
		const compiler = this.options.compiler;
		if (!compiler) {
			this.options.onEvent({
				state: "error",
				message: "没有可用的编译器，无法调试。"
			});
			return;
		}
		const gdb = compiler.executable.replace(/g\+\+\.exe$/i, "gdb.exe");
		if (!(0, node_fs.existsSync)(gdb)) {
			this.options.onEvent({
				state: "error",
				message: `这个编译器目录里没有 gdb.exe（找的是 ${gdb}）。\n调试需要 gdb；「预装编译器」那个版本是带的。`
			});
			return;
		}
		const env = { ...process.env };
		delete env.ELECTRON_RUN_AS_NODE;
		prependPath(env, compiler.binDir);
		this.options.onEvent({ state: "starting" });
		this.child = (0, node_child_process.spawn)(gdb, [
			"--quiet",
			"--interpreter=mi2",
			this.options.executable
		], {
			cwd: this.options.directory,
			env,
			windowsHide: true
		});
		this.child.stdout.setEncoding("utf8");
		this.child.stderr.setEncoding("utf8");
		this.child.stdout.on("data", (chunk) => this.consume(chunk));
		this.child.stderr.on("data", (chunk) => this.consume(chunk));
		this.child.on("error", (error) => {
			this.options.onEvent({
				state: "error",
				message: `gdb 启动失败：${error.message}`
			});
		});
		this.child.on("close", () => {
			this.clearTimer();
			if (!this.exited) {
				this.exited = true;
				this.options.onEvent({
					state: "exited",
					message: "调试已结束"
				});
			}
		});
		this.send("set confirm off");
		this.send("set pagination off");
		this.send("set print pretty off");
		this.send("set width 0");
		for (const breakpoint of this.options.breakpoints) {
			const normalized = breakpoint.file.replace(/\\/g, "/");
			this.send(`break ${normalized}:${breakpoint.line}`);
		}
		this.send("-exec-run");
		this.armTimeout();
	}
	armTimeout() {
		this.clearTimer();
		this.timer = setTimeout(() => {
			this.options.onEvent({
				state: "exited",
				message: `程序运行超过 ${DEBUG_RUN_TIMEOUT_MS / 1e3} 秒，已强制结束（是不是死循环？）`
			});
			this.stop();
		}, DEBUG_RUN_TIMEOUT_MS);
	}
	clearTimer() {
		if (this.timer) {
			clearTimeout(this.timer);
			this.timer = null;
		}
	}
	send(command) {
		if (!this.child || this.child.killed) return;
		this.child.stdin.write(`${command}\n`);
	}
	/** 继续 / 单步 */
	command(action) {
		if (!this.child || this.exited) return;
		this.armTimeout();
		this.send(`-exec-${action}`);
	}
	stop() {
		this.clearTimer();
		if (!this.child) return;
		try {
			this.send("-exec-interrupt");
			this.send("kill");
			this.send("quit");
		} catch {}
		setTimeout(() => this.kill(), 300);
	}
	kill() {
		if (this.child && !this.child.killed) this.child.kill();
		this.child = null;
	}
	/** 处理 gdb 的输出流（一次可能只来半行，需要缓冲） */
	consume(chunk) {
		this.buffer += chunk;
		let newlineAt = this.buffer.indexOf("\n");
		while (newlineAt !== -1) {
			const line = this.buffer.slice(0, newlineAt);
			this.buffer = this.buffer.slice(newlineAt + 1);
			this.handleLine(line);
			newlineAt = this.buffer.indexOf("\n");
		}
		if (this.buffer.length > 2e5) this.buffer = "";
	}
	handleLine(rawLine) {
		const line = rawLine.trimEnd();
		if (line.length === 0) return;
		const marker = line[0];
		const body = line.slice(1);
		if (marker === "~") {
			const [value] = parseValue(line, 1);
			const text = typeof value === "string" ? value : "";
			if (text) this.options.onEvent({ output: text });
			return;
		}
		if (marker === "*") {
			const { resultClass, rest } = splitResultClass(body);
			if (resultClass === "running") {
				this.options.onEvent({ state: "running" });
				return;
			}
			const record = parseRecord(rest);
			const reason = asString(record.reason);
			if (reason === "exited-normally" || reason === "exited") {
				this.exited = true;
				this.clearTimer();
				const code = asString(record.exitCode);
				this.options.onEvent({
					state: "exited",
					message: code ? `程序正常结束（退出码 ${code}）` : "程序正常结束"
				});
				return;
			}
			if (reason === "exited-signalled") {
				this.exited = true;
				this.clearTimer();
				this.options.onEvent({
					state: "exited",
					message: "程序被信号终止"
				});
				return;
			}
			const frame = asTuple(record.frame);
			const file = asString(frame.file);
			const lineNumber = Number(asString(frame.line)) || 0;
			this.clearTimer();
			const location = file ? {
				file,
				fullPath: asString(frame.fullname) || file,
				line: lineNumber,
				func: asString(frame.func)
			} : void 0;
			if (location) this.lastLocation = location;
			const label = reason === "breakpoint-hit" ? "命中断点" : reason === "end-stepping-range" ? "单步完成" : reason === "signal-received" ? "收到信号" : reason;
			this.options.onEvent({
				state: "paused",
				location,
				message: label
			});
			this.send("-stack-list-variables --simple-values");
			return;
		}
		if (marker === "^") {
			const { resultClass, rest } = splitResultClass(body);
			if (resultClass === "running") {
				this.options.onEvent({ state: "running" });
				return;
			}
			if (resultClass === "error") {
				if (this.exited) return;
				const record = parseRecord(rest);
				this.options.onEvent({
					state: "error",
					message: asString(record.msg) || "gdb 报错"
				});
				return;
			}
			const record = parseRecord(rest);
			if (record.variables) this.options.onEvent({
				state: "paused",
				location: this.lastLocation,
				variables: this.parseVariables(record.variables)
			});
			return;
		}
	}
	parseVariables(value) {
		if (!Array.isArray(value)) return [];
		const result = [];
		for (const item of value) {
			const tuple = asTuple(item);
			const name = asString(tuple.name);
			if (!name) continue;
			const shown = asString(tuple.value) || asString(tuple.type) || "（这个版本读不到值）";
			result.push({
				name,
				value: shown
			});
			if (result.length >= 60) break;
		}
		return result;
	}
};
//#endregion
//#region src/main/settings.ts
/**
* 设置持久化。
*
* 跨会话生效的偏好都在这里：编辑器外观（字号/字体/行号/ minimap…）、
* 下次启动要不要恢复上次的工作区、以及默认 C++ 标准。
* 落盘 userData/settings.json；读一次之后走内存缓存。
* 每次写入都做白名单校验 —— 坏值被丢掉并回落到默认值，而不是扩散下去。
*/
function settingsPath() {
	return (0, node_path.join)(electron.app.getPath("userData"), "settings.json");
}
var SETTINGS_DEFAULTS = {
	fontSize: 14,
	fontFamily: "Consolas, \"Courier New\", monospace",
	tabSize: 2,
	wordWrap: "off",
	lineNumbers: true,
	minimap: true,
	cursorBlinking: "smooth",
	smoothScrolling: true,
	renderWhitespace: "none",
	restoreWorkspace: true,
	lastWorkspaceRoot: "",
	cppStandard: "",
	language: "zh",
	uiTheme: "dark",
	ideTheme: "native"
};
var settingsCache = null;
function readSettingsFile() {
	try {
		const parsed = JSON.parse((0, node_fs.readFileSync)(settingsPath(), "utf8"));
		return typeof parsed === "object" && parsed !== null ? parsed : {};
	} catch {
		return {};
	}
}
/** 单个键的白名单校验。返回 undefined 表示「这个值不能用，用默认」。 */
function sanitizeSetting(key, value) {
	switch (key) {
		case "fontSize": {
			const size = Math.round(Number(value));
			return Number.isFinite(size) && size >= 8 && size <= 48 ? size : void 0;
		}
		case "tabSize": {
			const size = Math.round(Number(value));
			return Number.isFinite(size) && size >= 1 && size <= 8 ? size : void 0;
		}
		case "fontFamily":
			return typeof value === "string" && value.trim().length > 0 && value.length <= 200 ? value.trim() : void 0;
		case "wordWrap":
			return ["off", "on", "wordWrapColumn", "bounded"].includes(value) ? value : void 0;
		case "cursorBlinking":
			return ["blink", "smooth", "phase", "expand", "solid"].includes(value) ? value : void 0;
		case "renderWhitespace":
			return ["none", "boundary", "selection", "trailing", "all"].includes(value) ? value : void 0;
		case "lineNumbers":
		case "minimap":
		case "smoothScrolling":
		case "restoreWorkspace":
			return typeof value === "boolean" ? value : void 0;
		case "lastWorkspaceRoot":
			return typeof value === "string" && value.length > 0 && value.length <= 260 ? value : "";
		case "cppStandard":
			return ["", "auto", "c++11", "c++14", "c++17", "c++20", "c++23", "c++26"].includes(value) ? value : "";
		case "language":
			return ["zh", "en"].includes(value) ? value : void 0;
		case "uiTheme":
			return ["light", "dark"].includes(value) ? value : void 0;
		case "ideTheme":
			return ["native", "codeblocks", "devcpp", "geany"].includes(value) ? value : void 0;
		default:
			return void 0;
	}
}
function loadSettings() {
	if (settingsCache) return settingsCache;
	const stored = readSettingsFile();
	const merged = { ...SETTINGS_DEFAULTS };
	for (const key of Object.keys(SETTINGS_DEFAULTS)) {
		if (!(key in stored)) continue;
		const clean = sanitizeSetting(key, stored[key]);
		if (clean !== void 0) merged[key] = clean;
	}
	settingsCache = merged;
	return merged;
}
function saveSettings(update) {
	const current = loadSettings();
	if (typeof update === "object" && update !== null) {
		for (const [key, value] of Object.entries(update)) {
			if (!(key in SETTINGS_DEFAULTS)) continue;
			const clean = sanitizeSetting(key, value);
			if (clean !== void 0) current[key] = clean;
		}
	}
	try {
		(0, node_fs.mkdirSync)((0, node_path.dirname)(settingsPath()), { recursive: true });
		(0, node_fs.writeFileSync)(settingsPath(), JSON.stringify(current, null, 2), "utf8");
	} catch (error) {
		console.error("保存设置失败：", error);
	}
	return current;
}
//#endregion
//#region src/main/luogu.ts
/**
* 洛谷题库客户端。
*
* 为什么不用 fetch：洛谷会对每个请求先 302 到同一个 URL 并种一个 C3VK
* cookie，Node 的 fetch（undici）没有 cookie jar，会在重定向里打转。
* 所以用 node:https 手动跟随重定向 + 自管 cookie jar，最多 5 跳、
* 只允许 www.luogu.com.cn、12 秒超时、2MB 上限。
*
* 数据源是题目页/题库页内嵌的 <script id="lentille-context"> JSON，
* 比 HTML 解析稳得多。题面按 pid 缓存 5 分钟，重复打开秒回。
*/
var LUOGU_ORIGIN = "https://www.luogu.com.cn";
var LUOGU_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
var LUOGU_TIMEOUT_MS = 12e3;
var LUOGU_MAX_BYTES = 2097152;
var luoguCookieJar = /* @__PURE__ */ new Map();
var luoguProblemCache = /* @__PURE__ */ new Map();
var LUOGU_CACHE_TTL_MS = 3e5;
function luoguStoreCookies(host, setCookieHeaders) {
	if (!setCookieHeaders) return;
	const list = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
	let jar = luoguCookieJar.get(host);
	if (!jar) {
		jar = /* @__PURE__ */ new Map();
		luoguCookieJar.set(host, jar);
	}
	for (const raw of list) {
		const first = String(raw).split(";")[0];
		const eq = first.indexOf("=");
		if (eq <= 0) continue;
		jar.set(first.slice(0, eq).trim(), first.slice(eq + 1).trim());
	}
}
function luoguCookieHeader(host) {
	const jar = luoguCookieJar.get(host);
	if (!jar || jar.size === 0) return "";
	return [...jar.entries()].map(([name, value]) => `${name}=${value}`).join("; ");
}
function luoguGetText(url, depth = 0) {
	return new Promise((resolve, reject) => {
		if (depth > 5) {
			reject(new Error("洛谷返回了太多重定向，可能是网络问题"));
			return;
		}
		let parsed;
		try {
			parsed = new URL(url);
		} catch {
			reject(new Error(`URL 非法：${url}`));
			return;
		}
		if (parsed.protocol !== "https:" || parsed.hostname !== "www.luogu.com.cn") {
			reject(new Error("只允许访问 https://www.luogu.com.cn"));
			return;
		}
		const cookie = luoguCookieHeader(parsed.hostname);
		const request = node_https.get(parsed, {
			headers: {
				"user-agent": LUOGU_UA,
				accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
				"accept-language": "zh-CN,zh;q=0.9",
				...(cookie ? { cookie } : {})
			}
		}, (response) => {
			const status = response.statusCode ?? 0;
			const location = response.headers.location;
			luoguStoreCookies(parsed.hostname, response.headers["set-cookie"]);
			if (status >= 300 && status < 400 && location) {
				response.resume();
				luoguGetText(new URL(location, parsed).href, depth + 1).then(resolve, reject);
				return;
			}
			if (status !== 200) {
				response.resume();
				reject(new Error(`洛谷返回了 HTTP ${status}`));
				return;
			}
			const chunks = [];
			let total = 0;
			response.on("data", (chunk) => {
				total += chunk.length;
				if (total > LUOGU_MAX_BYTES) {
					request.destroy(new Error("页面太大，已停止下载"));
					return;
				}
				chunks.push(chunk);
			});
			response.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
			response.on("error", reject);
		});
		request.setTimeout(LUOGU_TIMEOUT_MS, () => {
			request.destroy(new Error("访问洛谷超时了，请检查网络连接"));
		});
		request.on("error", (error) => reject(error instanceof Error ? error : new Error(String(error))));
	});
}
function luoguExtractContext(html) {
	const marker = `<script id="lentille-context" type="application/json">`;
	const start = html.indexOf(marker);
	if (start < 0) return null;
	const jsonStart = start + marker.length;
	const end = html.indexOf("</script>", jsonStart);
	if (end < 0) return null;
	try {
		return JSON.parse(html.slice(jsonStart, end));
	} catch {
		return null;
	}
}
function luoguNormalizeProblem(raw, fallbackPid) {
	const contenu = raw.contenu ?? {};
	const limits = raw.limits ?? {};
	const time = Array.isArray(limits.time) ? limits.time : [];
	const memory = Array.isArray(limits.memory) ? limits.memory : [];
	const pid = String(raw.pid ?? fallbackPid ?? "");
	return {
		pid,
		title: String(contenu.name ?? raw.name ?? ""),
		difficulty: typeof raw.difficulty === "number" ? raw.difficulty : null,
		fullScore: typeof raw.fullScore === "number" ? raw.fullScore : null,
		background: typeof contenu.background === "string" ? contenu.background : "",
		description: typeof contenu.description === "string" ? contenu.description : "",
		formatI: typeof contenu.formatI === "string" ? contenu.formatI : "",
		formatO: typeof contenu.formatO === "string" ? contenu.formatO : "",
		hint: typeof contenu.hint === "string" ? contenu.hint : "",
		samples: Array.isArray(raw.samples) ? raw.samples.filter((pair) => Array.isArray(pair)).map((pair) => [String(pair[0] ?? ""), String(pair[1] ?? "")]) : [],
		timeLimitMs: time.length > 0 ? [Math.min(...time), Math.max(...time)] : null,
		memoryLimitKb: memory.length > 0 ? memory[0] : null,
		totalSubmit: typeof raw.totalSubmit === "number" ? raw.totalSubmit : null,
		totalAccepted: typeof raw.totalAccepted === "number" ? raw.totalAccepted : null,
		tags: Array.isArray(raw.tags) ? raw.tags.filter((tag) => typeof tag === "number") : [],
		provider: typeof raw.provider?.name === "string" ? raw.provider.name : "",
		url: `${LUOGU_ORIGIN}/problem/${encodeURIComponent(pid)}`
	};
}
async function luoguSearchProblems(options = {}) {
	const keyword = String(options.keyword ?? "").trim().slice(0, 40);
	const page = Math.min(Math.max(1, Math.floor(Number(options.page) || 1)), 500);
	const difficulty = /^[0-7]$/.test(String(options.difficulty ?? "")) ? String(options.difficulty) : "";
	const params = new URLSearchParams();
	if (keyword) params.set("keyword", keyword);
	params.set("page", String(page));
	if (difficulty) params.set("difficulty", difficulty);
	const html = await luoguGetText(`${LUOGU_ORIGIN}/problem/list?${params.toString()}`);
	const context = luoguExtractContext(html);
	const problems = context?.data?.problems;
	const result = Array.isArray(problems?.result) ? problems.result : [];
	const tags = {};
	const tagPattern = /href="\/problem\/list\?tag=(\d+)"[^>]*>([^<]+)<\/a>/g;
	let match;
	while ((match = tagPattern.exec(html)) !== null) {
		const id = Number(match[1]);
		const name = match[2].trim();
		if (Number.isFinite(id) && name) tags[id] = name;
	}
	return {
		items: result.map((item) => ({
			pid: String(item.pid ?? ""),
			title: String(item.name ?? ""),
			difficulty: typeof item.difficulty === "number" ? item.difficulty : null,
			totalSubmit: typeof item.totalSubmit === "number" ? item.totalSubmit : null,
			totalAccepted: typeof item.totalAccepted === "number" ? item.totalAccepted : null
		})).filter((item) => item.pid.length > 0),
		count: typeof problems?.count === "number" ? problems.count : result.length,
		perPage: typeof problems?.perPage === "number" ? problems.perPage : 50,
		page,
		tags
	};
}
async function luoguGetProblem(pid) {
	const id = String(pid ?? "").trim();
	if (!/^[A-Za-z]{1,3}[0-9][0-9A-Za-z]{0,7}$/.test(id)) throw new Error(`题目编号看起来不对：${id}`);
	const cached = luoguProblemCache.get(id);
	const now = Date.now();
	if (cached && now - cached.at < LUOGU_CACHE_TTL_MS) return cached.problem;
	let html;
	try {
		html = await luoguGetText(`${LUOGU_ORIGIN}/problem/${encodeURIComponent(id)}`);
	} catch (error) {
		if (/HTTP 404/.test(error?.message ?? "")) throw new Error(`洛谷上没有编号为 ${id} 的题目（可能编号写错了，或者这道题被隐藏了）`);
		throw error;
	}
	const context = luoguExtractContext(html);
	const raw = context?.data?.problem;
	if (!raw) throw new Error(`没有找到题目 ${id}，可能是编号写错了`);
	const problem = luoguNormalizeProblem(raw, id);
	luoguProblemCache.set(id, { at: now, problem });
	return problem;
}
//#endregion
//#region src/main/index.ts
registerAppSchemePrivileges();
mark("mainLoaded");
var mainWindow = null;
/** 保存 IPC 被调用的次数。基准用它验证"Ctrl+S 真的触发了保存"。 */
var saveFileCalls = 0;
/** 插件 id → 插件目录。协议层靠它把 app://plugin-<id>/ 映射到磁盘。 */
var pluginOrigins = /* @__PURE__ */ new Map();
var pluginHost = null;
/** 插件日志旁路，供基准判断"取消是否真的到达插件""未授权是否真的被拒绝" */
var pluginLogs = [];
/** 渲染层控制台旁路。渲染层出错时窗口是空白的，没有它就只能靠猜。 */
var rendererConsole = [];
/** 沙箱生命周期旁路：加载失败时往往什么都不报，只能靠这些事件定位 */
var pluginDebug = [];
/** 协议请求旁路：判断沙箱那次加载有没有走到协议层 */
var protocolLog = [];
function sendToRenderer(channel, payload) {
	if (!mainWindow || mainWindow.isDestroyed()) return;
	mainWindow.webContents.send(channel, payload);
}
/**
* 代码执行服务 —— 应用里唯一会真正运行用户代码的地方。
* 三道护栏都在 RunManager 内：超时杀进程树、输出字节上限、强制 UTF-8。
*/
var runManager = new RunManager({
	onStdout: (chunk) => sendToRenderer(RUN_CHANNELS.stdout, chunk),
	onStderr: (chunk) => sendToRenderer(RUN_CHANNELS.stderr, chunk),
	onFinished: (result) => sendToRenderer(RUN_CHANNELS.finished, result)
});
/** 各进程类型的工作集内存（MB）。内存是明确要覆盖的性能维度之一。 */
function collectMemoryMb() {
	const totals = {};
	for (const metric of electron.app.getAppMetrics()) {
		const key = metric.type.toLowerCase();
		const megabytes = (metric.memory?.workingSetSize ?? 0) / 1024;
		totals[key] = Math.round((totals[key] ?? 0) + megabytes);
	}
	return totals;
}
/**
* 滚动流畅度测量。
*
* 刻意用**真实滚轮输入事件**驱动，而不是调用 Monaco 的内部滚动 API：
* 后者测的是"API 调用有多快"，前者测的才是"用户滚动时掉不掉帧"。
*/
async function measureScroll(target, steps = 60) {
	const framePromise = target.webContents.executeJavaScript(`
    new Promise((resolve) => {
      const deltas = []
      let last = performance.now()
      function tick(now) {
        deltas.push(now - last)
        last = now
        if (deltas.length >= ${steps + 40}) resolve(deltas)
        else requestAnimationFrame(tick)
      }
      requestAnimationFrame(tick)
    })
  `);
	for (let step = 0; step < steps; step += 1) {
		target.webContents.sendInputEvent({
			type: "mouseWheel",
			x: 600,
			y: 400,
			deltaX: 0,
			deltaY: -120,
			wheelTicksX: 0,
			wheelTicksY: 1,
			canScroll: true
		});
		await new Promise((resolve) => setTimeout(resolve, 16));
	}
	return (await framePromise).slice(5, 5 + steps);
}
function createWindow() {
	const window = new electron.BrowserWindow({
		width: 1280,
		height: 820,
		minWidth: 800,
		minHeight: 560,
		show: false,
		backgroundColor: "#1f1f1f",
		title: "Sparkle IDE",
		autoHideMenuBar: true,
		webPreferences: {
			preload: (0, node_path.join)(__dirname, "../preload/index.js"),
			sandbox: true,
			contextIsolation: true,
			nodeIntegration: false,
			spellcheck: false
		}
	});
	window.once("ready-to-show", () => {
		mark("windowShown");
		window.show();
	});
	window.webContents.setWindowOpenHandler(({ url }) => {
		electron.shell.openExternal(url);
		return { action: "deny" };
	});
	window.webContents.on("console-message", (...args) => {
		const details = args[0];
		const message = typeof details?.message === "string" ? details.message : String(args[2] ?? "");
		if (!message) return;
		rendererConsole.push(String(message).slice(0, 500));
		if (rendererConsole.length > 200) rendererConsole.shift();
		recordDiagnostic("rendererConsole", rendererConsole);
	});
	window.loadURL(`${APP_ORIGIN}/index.html`);
	mainWindow = window;
	return window;
}
electron.app.whenReady().then(async () => {
	mark("appReady");
	const protocolOptions = {
		rendererDir: (0, node_path.join)(__dirname, "../renderer"),
		resolvePluginDir: (pluginId) => pluginOrigins.get(pluginId) ?? null,
		onRequest: (info) => {
			protocolLog.push(`${info.host}${info.pathname} → ${info.outcome}`);
			if (protocolLog.length > 100) protocolLog.shift();
			recordDiagnostic("protocolLog", protocolLog);
		}
	};
	serveCustomProtocols(protocolOptions);
	mark("protocolReady");
	pluginHost = new PluginHost({
		roots: process.env.SPARKLE_BENCH_PLUGIN_ROOT ? [process.env.SPARKLE_BENCH_PLUGIN_ROOT] : [.../* @__PURE__ */ new Set([
			(0, node_path.join)(electron.app.getAppPath(), "plugins"),
			(0, node_path.join)(process.cwd(), "plugins"),
			(0, node_path.join)(electron.app.getPath("userData"), "plugins")
		])],
		preloadPath: (0, node_path.join)(__dirname, "../preload/plugin.js"),
		registerOrigin: (pluginId, directory) => pluginOrigins.set(pluginId, directory),
		notifyRenderer: (payload) => sendToRenderer(PLUGIN_CHANNELS.changed, payload),
		currentWorkspaceRoot: () => currentWorkspace().root,
		prepareSession: (partition) => serveCustomProtocolsForPartition(partition, protocolOptions),
		onPluginLog: (pluginId, message) => {
			pluginLogs.push(`${pluginId}: ${message}`);
			recordDiagnostic("pluginLogs", pluginLogs);
		},
		onPluginDebug: (message) => {
			pluginDebug.push(message);
			if (pluginDebug.length > 200) pluginDebug.shift();
			recordDiagnostic("pluginDebug", pluginDebug);
		}
	});
	await pluginHost.initialize();
	mark("pluginsReady");
	electron.ipcMain.handle(RUN_CHANNELS.interpreter, () => interpreterInfo());
	electron.ipcMain.handle(RUN_CHANNELS.start, (_event, request) => runManager.start(request));
	electron.ipcMain.handle(RUN_CHANNELS.stop, (_event, runId) => runManager.stop(runId));
	electron.ipcMain.handle(FS_CHANNELS.openFolder, async () => {
		const workspace = await openFolder(mainWindow);
		if (workspace.root) saveSettings({ lastWorkspaceRoot: workspace.root });
		return workspace;
	});
	electron.ipcMain.handle(FS_CHANNELS.currentWorkspace, () => currentWorkspace());
	electron.ipcMain.handle(FS_CHANNELS.readDirectory, (_event, path) => readDirectory(path ?? ""));
	electron.ipcMain.handle(FS_CHANNELS.readFile, (_event, path) => readFileContent(path));
	electron.ipcMain.handle(FS_CHANNELS.saveFile, (_event, path, content) => {
		saveFileCalls += 1;
		return saveFile(path, content);
	});
	electron.ipcMain.handle(PLUGIN_CHANNELS.openFolder, async () => {
		const directory = (0, node_path.join)(electron.app.getPath("userData"), "plugins");
		await (0, node_fs_promises.mkdir)(directory, { recursive: true });
		electron.shell.openPath(directory);
		return directory;
	});
	registerToolchainIpc((progress) => sendToRenderer(TOOLCHAIN_CHANNELS.progress, progress), () => mainWindow);
	const requireRoot = () => {
		const root = currentWorkspace().root;
		if (!root) throw new Error("尚未打开文件夹");
		return root;
	};
	electron.ipcMain.handle(FS_CHANNELS.createFile, (_event, parent, name) => createFile(requireRoot(), parent ?? "", name));
	electron.ipcMain.handle(FS_CHANNELS.createDirectory, (_event, parent, name) => createDirectory(requireRoot(), parent ?? "", name));
	electron.ipcMain.handle(FS_CHANNELS.renameEntry, (_event, path, newName) => renameEntry(requireRoot(), path, newName));
	electron.ipcMain.handle(FS_CHANNELS.deleteEntry, (_event, path, recursive) => deleteEntry(requireRoot(), path, recursive === true));
	electron.ipcMain.handle(BUILD_CHANNELS.scan, () => scanProjects(requireRoot()));
	electron.ipcMain.handle(BUILD_CHANNELS.ensureCMakeLists, (_event, project) => ensureCMakeLists(requireRoot(), project));
	electron.ipcMain.handle(BUILD_CHANNELS.compile, async (_event, request) => {
		const compiler = currentCompiler();
		if (request.language === "cpp" && !compiler) return {
			ok: false,
			output: "",
			durationMs: 0,
			friendlyError: "没有找到 C++ 编译器。到「工具链」面板里选一个，或者点一键下载。"
		};
		return compileProject(requireRoot(), compiler, request);
	});
	electron.ipcMain.handle(BUILD_CHANNELS.run, async (_event, request, executable) => {
		const compiler = currentCompiler();
		const pythonExecutable = detect().find((tool) => tool.id === "python")?.path ?? "python";
		return runProject(requireRoot(), compiler, request, executable, pythonExecutable);
	});
	electron.ipcMain.handle(SEARCH_CHANNELS.query, (_event, options) => searchWorkspace(requireRoot(), options));

/**
 * 洛谷写题「测样例」：编译当前文件 → 用样例输入喂 stdin 跑一遍 → 与期望输出比对。
 * 判定：CE 编译失败 / TLE 超时 / RE 运行错误 / WA 答案错误 / AC 通过 / RUN 仅运行
 */
async function runSample(root, compiler, request) {
	const startedAt = Date.now();
	const compiled = await compileSingleFile(root, compiler, { path: request.path });
	if (!compiled.ok) return {
		verdict: "CE",
		message: compiled.friendlyError || "编译失败",
		stdout: "",
		stderr: compiled.output || "",
		expected: String(request.expected ?? ""),
		input: String(request.input ?? ""),
		durationMs: Date.now() - startedAt
	};
	const executable = compiled.executable;
	const directory = (0, node_path.dirname)(executable);
	const env = { ...process.env };
	delete env.ELECTRON_RUN_AS_NODE;
	if (compiler && compiler.binDir) prependPath(env, compiler.binDir);
	const limit = Math.max(1000, Number(request.timeLimitMs) || 5000);
	const run = await new Promise((resolve) => {
		let stdout = "", stderr = "", timedOut = false, settled = false;
		const finish = (value) => { if (!settled) { settled = true; resolve(value); } };
		let child;
		try {
			child = (0, node_child_process.spawn)(executable, [], { cwd: directory, env, windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
		} catch (error) {
			finish({ code: -1, stdout: "", stderr: String(error?.message ?? error), timedOut: false });
			return;
		}
		const timer = setTimeout(() => { timedOut = true; try { child.kill(); } catch (e) { } }, limit);
		child.stdout.on("data", (chunk) => { stdout += chunk.toString("utf8"); });
		child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8"); });
		child.on("error", (error) => { clearTimeout(timer); finish({ code: -1, stdout, stderr: stderr + String(error?.message ?? error), timedOut }); });
		child.on("close", (code) => { clearTimeout(timer); finish({ code: code ?? -1, stdout, stderr, timedOut }); });
		try {
			child.stdin.write(String(request.input ?? ""));
			child.stdin.end();
		} catch (e) { }
	});
	const normalize = (text) => String(text ?? "").replace(/\r\n?/g, "\n").split("\n").map((line) => line.replace(/[ \t]+$/g, "")).join("\n").trim();
	const expected = normalize(request.expected);
	const actual = normalize(run.stdout);
	let verdict;
	if (run.timedOut) verdict = "TLE";
	else if (run.code !== 0) verdict = "RE";
	else if (!expected) verdict = "RUN";
	else if (actual === expected) verdict = "AC";
	else verdict = "WA";
	return {
		verdict,
		stdout: run.stdout,
		stderr: run.stderr,
		expected: String(request.expected ?? ""),
		input: String(request.input ?? ""),
		exitCode: run.code,
		timedOut: run.timedOut,
		durationMs: Date.now() - startedAt
	};
}
	electron.ipcMain.handle(IDE_CHANNELS.compileFile, (_event, request) => compileSingleFile(requireRoot(), currentCompiler(), request));
	electron.ipcMain.handle("ide:runSample", async (_event, request) => {
		try { return await runSample(requireRoot(), currentCompiler(), request ?? {}); }
		catch (error) { return { verdict: "ERR", message: String(error?.message ?? error) }; }
	});
	electron.ipcMain.handle(IDE_CHANNELS.runFile, (_event, request) => runExecutable(requireRoot(), currentCompiler(), detect().find((tool) => tool.id === "python")?.path ?? "python", request));
	electron.ipcMain.handle(IDE_CHANNELS.runInConsole, (_event, request) => runInConsole(requireRoot(), currentCompiler(), request.executable, request.language, detect().find((tool) => tool.id === "python")?.path ?? "python"));
	electron.ipcMain.handle("luogu:search", (_event, options) => luoguSearchProblems(options ?? {}));
	electron.ipcMain.handle("luogu:problem", (_event, pid) => luoguGetProblem(pid));
	/** 打开洛谷题目页。只允许 https://www.luogu.com.cn/problem/<编号>，别处一律拒绝 */
	electron.ipcMain.handle("luogu:openExternal", async (_event, url) => {
		let parsed;
		try {
			parsed = new URL(String(url ?? ""));
		} catch {
			return { ok: false, error: "链接格式不对" };
		}
		if (parsed.protocol !== "https:" || parsed.hostname !== "www.luogu.com.cn" || !/^\/problem\/[A-Za-z]{1,3}[0-9][0-9A-Za-z]{0,7}$/.test(parsed.pathname)) return { ok: false, error: "只能打开洛谷题目页面" };
		await electron.shell.openExternal(parsed.href);
		return { ok: true };
	});
	electron.ipcMain.handle("settings:get", () => loadSettings());
	electron.ipcMain.handle("settings:set", (_event, update) => saveSettings(update));
	/** 关于信息（版本号、工作区、数据目录都给「设置」面板用） */
	electron.ipcMain.handle("ide:appInfo", () => ({
		version: electron.app.getVersion(),
		electron: process.versions.electron,
		chrome: process.versions.chrome,
		node: process.versions.node,
		workspace: currentWorkspace(),
		userData: electron.app.getPath("userData")
	}));
	/** 在资源管理器里显示某个路径（设置面板「打开数据目录」用） */
	electron.ipcMain.handle("ide:openPath", async (_event, target) => {
		const path = String(target ?? "");
		if (!path) return { ok: false, error: "路径为空" };
		try {
			if (!(0, node_fs.existsSync)(path)) return { ok: false, error: `路径不存在：${path}` };
			const error = await electron.shell.openPath(path);
			return error ? { ok: false, error } : { ok: true };
		} catch (error) {
			return { ok: false, error: String(error?.message ?? error) };
		}
	});
	/** 不经对话框直接设定工作区（启动时恢复上次工作区用） */
	electron.ipcMain.handle("ide:setWorkspace", (_event, directory) => {
		const target = String(directory ?? "");
		if (!target || !(0, node_fs.existsSync)(target) || !(0, node_fs.statSync)(target).isDirectory()) return { ok: false, error: `目录不存在：${target}` };
		setWorkspaceRoot(target);
		return { ok: true, workspace: currentWorkspace() };
	});
	/**
	* 打开单个文件。
	*
	* 选的文件不在当前工作区里时，就把工作区切到它所在的目录再打开 ——
	* 用户点「打开文件」的意图就是"我要弄这个文件"，
	* 先让他自己去打开文件夹是多余的步骤。
	*/
	electron.ipcMain.handle(IDE_CHANNELS.openFileDialog, async () => {
		const options = {
			title: "打开文件",
			properties: ["openFile"],
			filters: [{
				name: "代码文件",
				extensions: [
					"cpp",
					"cc",
					"cxx",
					"c",
					"h",
					"hpp",
					"py",
					"js",
					"ts",
					"json",
					"md",
					"txt"
				]
			}, {
				name: "所有文件",
				extensions: ["*"]
			}]
		};
		const result = mainWindow ? await electron.dialog.showOpenDialog(mainWindow, options) : await electron.dialog.showOpenDialog(options);
		if (result.canceled || result.filePaths.length === 0) return {
			ok: false,
			cancelled: true
		};
		const picked = (0, node_path.resolve)(result.filePaths[0]);
		const root = currentWorkspace().root;
		if (!(root ? picked.toLowerCase().startsWith(`${(0, node_path.resolve)(root).toLowerCase()}\\`) : false)) setWorkspaceRoot((0, node_path.dirname)(picked));
		const workspaceRoot = (0, node_path.resolve)(currentWorkspace().root ?? (0, node_path.dirname)(picked));
		const relative = picked.slice(workspaceRoot.length).replace(/^[\\/]+/, "").replace(/\\/g, "/");
		return {
			ok: true,
			workspace: currentWorkspace(),
			path: relative
		};
	});
	let debugSession = null;
	electron.ipcMain.handle(IDE_CHANNELS.debugStart, async (_event, request) => {
		debugSession?.stop();
		debugSession = null;
		const root = requireRoot();
		const compiler = currentCompiler();
		if (!compiler) return {
			ok: false,
			error: "没有可用的编译器，无法调试。"
		};
		debugSession = new DebugSession({
			executable: request.executable,
			directory: request.directory ? (0, node_path.join)(root, request.directory) : root,
			breakpoints: request.breakpoints.map((item) => ({
				file: (0, node_path.join)(root, item.path),
				line: item.line
			})),
			compiler,
			onEvent: (event) => sendToRenderer(IDE_CHANNELS.debugEvent, event)
		});
		debugSession.start();
		return { ok: true };
	});
	electron.ipcMain.handle(IDE_CHANNELS.debugCommand, (_event, action) => {
		debugSession?.command(action);
		return { ok: true };
	});
	electron.ipcMain.handle(IDE_CHANNELS.debugStop, () => {
		debugSession?.stop();
		debugSession = null;
		return { ok: true };
	});
	const bench = benchConfig();
	electron.ipcMain.handle(BENCH_CHANNELS.config, () => bench);
	electron.ipcMain.on(BENCH_CHANNELS.mark, (_event, rendererMark) => recordRendererMark(rendererMark));
	if (bench.workspace) setWorkspaceRoot(bench.workspace);
	createWindow();
	mainWindow?.webContents.once("did-finish-load", () => {
		setTimeout(() => {
			const startedAt = Date.now();
			try {
				const tools = detect();
				recordDiagnostic("toolchain", {
					elapsedMs: Date.now() - startedAt,
					tools: tools.map((tool) => ({
						id: tool.id,
						available: tool.available,
						version: tool.version,
						source: tool.source,
						candidates: tool.candidates?.length ?? 0
					}))
				});
			} catch (error) {
				recordDiagnostic("toolchain", {
					elapsedMs: Date.now() - startedAt,
					error: error instanceof Error ? error.message : String(error)
				});
			}
		}, 400);
	});
	if (benchEnabled) {
		electron.ipcMain.once(BENCH_CHANNELS.rendererReady, async (_event, info) => {
			mark("rendererReady");
			recordRendererInfo(info);
			if (mainWindow && !mainWindow.isDestroyed()) try {
				const view = process.env.SPARKLE_BENCH_VIEW;
				if (view && /^[a-z]+$/.test(view)) {
					await mainWindow.webContents.executeJavaScript(`document.querySelector('[data-view="${view}"]')?.click(); true`);
					await new Promise((resolve) => setTimeout(resolve, 700));
				}
				if (process.env.SPARKLE_BENCH_RUN === "1") {
					await mainWindow.webContents.executeJavaScript(`document.querySelector('[data-action="run"]')?.click(); true`);
					await new Promise((resolve) => setTimeout(resolve, 2500));
				}
				const expand = process.env.SPARKLE_BENCH_EXPAND;
				if (expand) {
					await mainWindow.webContents.executeJavaScript(`document.querySelector('[data-tree-path="${expand.replace(/"/g, "")}"]')?.click(); true`);
					await new Promise((resolve) => setTimeout(resolve, 500));
				}
				if (process.env.SPARKLE_BENCH_SAVE === "1") {
					mainWindow.focus();
					mainWindow.webContents.focus();
					await new Promise((resolve) => setTimeout(resolve, 250));
					const callsBefore = saveFileCalls;
					await mainWindow.webContents.executeJavaScript(`
                window.dispatchEvent(new KeyboardEvent('keydown', {
                  key: 's', ctrlKey: true, bubbles: true, cancelable: true
                })); true
              `);
					await new Promise((resolve) => setTimeout(resolve, 600));
					recordDiagnostic("saveShortcutTriggered", saveFileCalls > callsBefore);
					const marker = (process.env.SPARKLE_BENCH_SAVE_MARKER ?? "saved_by_bench").replace(/[^A-Za-z0-9_]/g, "");
					recordDiagnostic("saveRoundTrip", await mainWindow.webContents.executeJavaScript(`
                (async () => {
                  const beforeFile = await window.sparkle.fs.readFile('main.py')
                  const next = beforeFile.content + "\\n# ${marker}\\n"
                  const saved = await window.sparkle.fs.saveFile('main.py', next)
                  const afterFile = await window.sparkle.fs.readFile('main.py')
                  return {
                    savedBytes: saved.bytes,
                    readBackContainsMarker: afterFile.content.includes('${marker}')
                  }
                })()
              `));
					mark("saveAttempted");
				}
				if (process.env.SPARKLE_BENCH_PLUGIN === "1") {
					recordDiagnostic("pluginCheck", await mainWindow.webContents.executeJavaScript(`
                (async () => {
                  const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

                  // 1) Python 补全：应由零权限的 python-helper 提供
                  const python = await window.sparkle.plugin.provideCompletions({
                    requestId: 'bench-python',
                    languageId: 'python',
                    context: { languageId: 'python', linePrefix: 'pri', lineNumber: 1, precedingLines: [] }
                  })

                  // 2) JavaScript 补全：慢速插件，请求后中途取消
                  const requestId = 'bench-cancel'
                  const pending = window.sparkle.plugin.provideCompletions({
                    requestId,
                    languageId: 'javascript',
                    context: { languageId: 'javascript', linePrefix: 'x', lineNumber: 1, precedingLines: [] }
                  })
                  await wait(700)
                  const cancelAccepted = await window.sparkle.plugin.cancel(requestId)
                  const cancelled = await pending

                  // 3) 权限探针：未申请权限却尝试读文件，应当被拒
                  await window.sparkle.plugin.activate('sparkle.perm-probe')
                  await wait(600)

                  const list = await window.sparkle.plugin.list()

                  return {
                    pythonLabels: python.items.map((item) => item.label),
                    pythonProviders: python.providers,
                    pythonNoProvider: python.noProvider,
                    pythonElapsedMs: python.elapsedMs,
                    cancelAccepted,
                    cancelledItems: cancelled.items.length,
                    plugins: list.plugins.map((plugin) => ({
                      id: plugin.id,
                      state: plugin.state,
                      requested: plugin.requested,
                      granted: plugin.granted,
                      sandboxAlive: plugin.sandboxAlive,
                      error: plugin.error
                    }))
                  }
                })()
              `));
					mark("pluginChecked");
				}
				if (process.env.SPARKLE_BENCH_PLUGIN_SCALE === "1") {
					recordDiagnostic("pluginScale", await mainWindow.webContents.executeJavaScript(`
                (async () => {
                  const before = await window.sparkle.plugin.list()
                  const startedAt = performance.now()
                  await Promise.all(
                    before.plugins.map((plugin) => window.sparkle.plugin.activate(plugin.id))
                  )
                  const activateAllMs = Math.round(performance.now() - startedAt)
                  const after = await window.sparkle.plugin.list()
                  return {
                    installed: before.plugins.length,
                    active: after.plugins.filter((p) => p.state === 'active').length,
                    errored: after.plugins.filter((p) => p.state === 'error').length,
                    activateAllMs
                  }
                })()
              `));
					mark("pluginScaleDone");
				}
				const settleMs = Number(process.env.SPARKLE_BENCH_SETTLE_MS ?? 900);
				if (settleMs > 0) await new Promise((resolve) => setTimeout(resolve, settleMs));
				try {
					recordDiagnostic("statusBarText", await mainWindow.webContents.executeJavaScript(`document.querySelector('.status-bar')?.textContent?.replace(/\\s+/g, ' ').trim() ?? ''`));
				} catch {}
				try {
					recordDiagnostic("toolchainProbe", await mainWindow.webContents.executeJavaScript(`
                (async () => {
                  const api = window.sparkle?.toolchain
                  if (!api || typeof api.detect !== 'function') {
                    return { ok: false, reason: 'preload 没有暴露 toolchain.detect', sparkleKeys: Object.keys(window.sparkle ?? {}) }
                  }
                  try {
                    const tools = await api.detect()
                    return { ok: true, count: tools.length, tools: tools.map((t) => t.id + ':' + (t.available ? t.version : 'missing')) }
                  } catch (error) {
                    return { ok: false, reason: 'invoke 失败：' + String(error) }
                  }
                })()
              `));
				} catch (error) {
					recordDiagnostic("toolchainProbe", {
						ok: false,
						reason: `执行探针本身失败：${error instanceof Error ? error.message : String(error)}`
					});
				}
				try {
					const readVisibleText = () => mainWindow.webContents.executeJavaScript(`(() => {
                    const el = document.querySelector('.monaco-editor .view-lines')
                    return el ? el.textContent : ''
                  })()`);
					mainWindow.focus();
					mainWindow.webContents.focus();
					await new Promise((resolve) => setTimeout(resolve, 300));
					const beforeText = await readVisibleText();
					await mainWindow.webContents.executeJavaScript(`(() => {
                  const el = document.querySelector('.monaco-editor .view-lines')
                  if (el) { const r = el.getBoundingClientRect(); el.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, clientX: r.x + 40, clientY: r.y + 10 })) }
                  return true
                })()`);
					await new Promise((resolve) => setTimeout(resolve, 300));
					for (const char of "ZZZ") {
						mainWindow.webContents.sendInputEvent({
							type: "char",
							keyCode: char
						});
						await new Promise((resolve) => setTimeout(resolve, 120));
					}
					await new Promise((resolve) => setTimeout(resolve, 800));
					const afterText = await readVisibleText();
					recordDiagnostic("typingTest", {
						beforeLength: beforeText.length,
						afterLength: afterText.length,
						changed: beforeText !== afterText,
						containsZZZ: afterText.includes("ZZZ"),
						beforeSample: beforeText.slice(0, 120),
						afterSample: afterText.slice(0, 120)
					});
				} catch (error) {
					recordDiagnostic("typingTest", { error: error instanceof Error ? error.message : String(error) });
				}
				try {
					recordDiagnostic("editorProbe", await mainWindow.webContents.executeJavaScript(`
                (async () => {
                  const label = (b) => (b.textContent || '').replace(/\\s+/g, ' ').trim()
                  const result = {}

                  // ── 1. 编辑器到底能不能输入 ──
                  const monaco = document.querySelector('.monaco-editor')
                  const inputArea = document.querySelector(
                    '.monaco-editor textarea, .monaco-editor .ime-text-area, .monaco-editor [contenteditable]'
                  )
                  result.editor = {
                    monacoExists: !!monaco,
                    monacoClass: monaco ? monaco.className.slice(0, 200) : '',
                    inputTag: inputArea ? inputArea.tagName : '(没有输入区)',
                    readOnlyAttr: inputArea ? (inputArea.getAttribute('readonly') || '') : '',
                    ariaReadonly: inputArea ? (inputArea.getAttribute('aria-readonly') || '') : '',
                    contentEditable: inputArea ? (inputArea.getAttribute('contenteditable') || '') : '',
                    editorHeight: monaco ? Math.round(monaco.getBoundingClientRect().height) : 0,
                    editorWidth: monaco ? Math.round(monaco.getBoundingClientRect().width) : 0
                  }

                  // ── 2. 工具栏按钮状态 ──
                  const buttons = [...document.querySelectorAll('.editor-toolbar button')]
                  result.buttons = buttons.map((b) => ({ label: label(b), disabled: b.disabled }))

                  // ── 3. 底部面板有哪些标签（用户说的"终端"多半就是它）──
                  result.panelTabs = [...document.querySelectorAll('.debug-panel .tabs button')].map(label)

                  const compile = buttons.find((b) => label(b).includes('编译并运行'))
                  if (!compile) return { ok: false, reason: '找不到「编译并运行」按钮', ...result }
                  if (compile.disabled) {
                    return { ok: false, reason: '「编译并运行」按钮是禁用的（多半是没打开文件）', ...result }
                  }

                  compile.click()
                  await new Promise((r) => setTimeout(r, 8000))

                  const panel = document.querySelector('.debug-panel')
                  result.friendly = ((document.querySelector('.debug-panel .friendly') || {}).textContent || '')
                    .replace(/\\s+/g, ' ').trim().slice(0, 400)
                  result.outputText = ((document.querySelector('.debug-panel .output') || {}).textContent || '')
                    .replace(/\\s+/g, ' ').trim().slice(0, 700)
                  result.panelText = (panel ? panel.textContent : '')
                    .replace(/\\s+/g, ' ').trim().slice(0, 900)
                  result.ok = true
                  return result
                })()
              `));
				} catch (error) {
					recordDiagnostic("editorProbe", {
						ok: false,
						reason: `探针执行失败：${error instanceof Error ? error.message : String(error)}`
					});
				}
				const shotPath = process.env.SPARKLE_BENCH_SHOT;
				if (shotPath) {
					const image = await mainWindow.webContents.capturePage();
					(0, node_fs.writeFileSync)(shotPath, image.toPNG());
					mark("screenshotSaved");
				}
			} catch (error) {
				console.error("基准动作执行失败:", error);
			}
			if (process.env.SPARKLE_BENCH_SCROLL === "1" && mainWindow && !mainWindow.isDestroyed()) try {
				recordScrollFrames(await measureScroll(mainWindow));
				mark("scrollMeasured");
			} catch (error) {
				console.error("滚动测量失败:", error);
			}
			recordMemory(collectMemoryMb());
			reportAndQuit(electron.app);
		});
		setTimeout(() => {
			mark("rendererTimeout");
			reportAndQuit(electron.app);
		}, 2e4).unref();
	}
	electron.app.on("activate", () => {
		if (electron.BrowserWindow.getAllWindows().length === 0) createWindow();
	});
});
electron.app.on("window-all-closed", () => {
	if (process.platform !== "darwin") electron.app.quit();
});
electron.app.on("before-quit", () => {
	runManager.stopAll();
	pluginHost?.disposeAll();
});
//#endregion
