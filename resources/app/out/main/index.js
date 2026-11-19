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
let node_stream = require("node:stream");
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
* connect-src 放开到 *：插件拿到 network 授权后可以像普通网页一样
* 自己 fetch / WebSocket / EventSource，不再强制走主进程代理。
*
* 代价说清楚：流量从此绕开主进程，**宿主看不到也拦不住**。
* 这是"插件同级权限"必然要接受的交换 —— 想要审计就只能禁掉原生联网。
*
* 其余指令仍然从 default-src 'none' 起步逐项放开：
* 插件没有 frame / object / 表单提交能力，脚本只能加载自己目录里的文件。
*/
var PLUGIN_CSP = [
	"default-src 'none'",
	"script-src 'self'",
	"style-src 'self' 'unsafe-inline'",
	"img-src 'self' data:",
	"font-src 'self' data:",
	"connect-src *",
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
	}, {
		/*
		* 背景媒体（图片 / 视频）专用协议。
		*
		* 为什么不用 file://：渲染层跑在 app:// 源上，file:// 会被安全策略拦掉；
		* 为什么不用 data URL：视频动辄几百 MB，base64 会把内存顶穿，而且没法拖动进度条。
		* stream: true 让 <video> 可以走 Range 请求边下边播。
		* 只服务"当前选中的那一个文件"，不做目录映射 —— 这样即使渲染层被注入，
		* 也读不到任意磁盘文件。
		*/
		scheme: "sparkle-media",
		privileges: {
			standard: true,
			secure: true,
			supportFetchAPI: true,
			corsEnabled: true,
			stream: true,
			bypassCSP: true
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
	"fs:read",
	"fs:write",
	"network",
	"process",
	"editor",
	"config"
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
	getActiveDocument: "plugin:getActiveDocument",
	applyEdits: "plugin:applyEdits",
	formatDocument: "plugin:formatDocument",
	listFormatters: "plugin:listFormatters",
	listCommands: "plugin:listCommands",
	executeCommand: "plugin:executeCommand",
	editorRequest: "plugin:editorRequest",
	editorReply: "plugin:editorReply",
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
var MAX_EDIT_TEXT = 2e4;
/**
* 清洗插件发来的编辑列表。
*
* 插件的返回值/请求参数都是**跨越隔离边界的不可信输入**，
* 这里逐项校验并截断，越界的编辑直接丢弃（不是 clamp ——
* clamp 会让一次错误的编辑悄悄改到文件末尾，比拒绝更糟）。
*/
function sanitizeEdits(value) {
	if (!Array.isArray(value)) return [];
	const result = [];
	for (const raw of value) {
		if (result.length >= 100) break;
		if (!raw || typeof raw !== "object") continue;
		const edit = raw;
		const num = (input) => {
			const n = Number(input);
			return Number.isFinite(n) && n >= 1 ? Math.floor(n) : 0;
		};
		const startLine = num(edit.startLine);
		const startColumn = num(edit.startColumn);
		const endLine = num(edit.endLine);
		const endColumn = num(edit.endColumn);
		if (!startLine || !startColumn || !endLine || !endColumn) continue;
		const text = typeof edit.text === "string" ? edit.text.slice(0, MAX_EDIT_TEXT) : "";
		result.push({
			startLine,
			startColumn,
			endLine,
			endColumn,
			text
		});
	}
	return result;
}
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
/**
* 「同级权限」的文件与配置能力。
*
* 和 workspace.* 的区别：
*   · workspace.* 只认工作区内的相对路径，是给"项目插件"用的；
*   · fs.* 认任意绝对路径，等价于主程序自己手里的 fs。
*
* 唯一的硬约束在**写**方向的两处：插件目录和 IDE 自己的设置/授权文件。
* 前者挡住"插件把自己复制进去，变成卸不掉的常驻程序"，
* 后者挡住"插件改设置给自己提权"。这两条不是审计，是功能正确性 ——
* 没有它们，设置里的权限开关可以被插件自己改掉。
*/
var MAX_ANY_FILE_BYTES = 64 * 1024 * 1024;
var MAX_DIR_ENTRIES = 2e3;
function pluginGuardPaths() {
	const userData = electron.app.getPath("userData");
	return {
		plugins: (0, node_path.join)(userData, "plugins"),
		files: [
			(0, node_path.join)(userData, "plugin-grants.json"),
			(0, node_path.join)(userData, "settings.json")
		]
	};
}
function pathInside(parent, target) {
	const rel = (0, node_path.relative)(String(parent).toLowerCase(), String(target).toLowerCase());
	return rel === "" || (!rel.startsWith("..") && !(0, node_path.isAbsolute)(rel));
}
function resolveAnyPath(root, rawPath) {
	const raw = String(rawPath ?? "").trim();
	if (!raw) throw new Error("path 不能为空");
	return (0, node_path.isAbsolute)(raw) ? (0, node_path.resolve)(raw) : (0, node_path.resolve)(root || process.cwd(), raw);
}
/**
* 解析真实路径。
*
* 只做字面量比较是不够的：插件可以先在别处建一个指向 settings.json 的符号链接，
* 再往链接上写 —— 字面上它写的不是受保护文件，实际改的却是。
* 所以校验必须落在 realpath 上；目标还不存在时，退一步解析它的父目录。
*/
async function realTarget(target) {
	try {
		return await (0, node_fs_promises.realpath)(target);
	} catch {
		try {
			const dir = await (0, node_fs_promises.realpath)((0, node_path.dirname)(target));
			return (0, node_path.join)(dir, (0, node_path.basename)(target));
		} catch {
			return target;
		}
	}
}
async function assertWritable(target) {
	const real = await realTarget(target);
	const guard = pluginGuardPaths();
	const pluginsReal = await realTarget(guard.plugins);
	if (pathInside(pluginsReal, real)) throw new Error(`拒绝写入插件目录：${real}（插件不能给自己写新版本）`);
	for (const file of guard.files) {
		const fileReal = await realTarget(file);
		if (String(fileReal).toLowerCase() === String(real).toLowerCase()) throw new Error(`拒绝直接写入 ${(0, node_path.basename)(fileReal)}：改设置请用 config.set`);
	}
}
async function fsReadAny(target, encoding) {
	let info;
	try {
		info = await (0, node_fs_promises.stat)(target);
	} catch {
		throw new Error(`文件不存在：${target}`);
	}
	if (info.isDirectory()) throw new Error(`这是一个目录，请用 fs.readdir：${target}`);
	if (info.size > MAX_ANY_FILE_BYTES) throw new Error(`文件太大（${info.size} 字节，上限 ${MAX_ANY_FILE_BYTES}）`);
	const buffer = await (0, node_fs_promises.readFile)(target);
	const wantBase64 = String(encoding || "utf8") === "base64";
	return {
		path: target,
		bytes: buffer.byteLength,
		binary: buffer.subarray(0, 8e3).includes(0),
		encoding: wantBase64 ? "base64" : "utf8",
		content: wantBase64 ? buffer.toString("base64") : buffer.toString("utf8")
	};
}
async function fsWriteAny(target, content, encoding) {
	await assertWritable(target);
	const data = String(encoding || "utf8") === "base64" ? Buffer.from(String(content ?? ""), "base64") : String(content ?? "");
	await (0, node_fs_promises.mkdir)((0, node_path.dirname)(target), { recursive: true });
	await (0, node_fs_promises.writeFile)(target, data);
	return {
		path: target,
		bytes: Buffer.byteLength(data)
	};
}
function pluginGrantsPath() {
	return (0, node_path.join)(electron.app.getPath("userData"), "plugin-grants.json");
}
async function loadPluginGrants() {
	try {
		const text = await (0, node_fs_promises.readFile)(pluginGrantsPath(), "utf8");
		const parsed = JSON.parse(text.replace(/^\uFEFF/, ""));
		return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
	} catch {
		return {};
	}
}
async function savePluginGrants(map) {
	try {
		const file = pluginGrantsPath();
		await (0, node_fs_promises.mkdir)((0, node_path.dirname)(file), { recursive: true });
		await (0, node_fs_promises.writeFile)(file, `${JSON.stringify(map, null, 2)}\n`, "utf8");
	} catch (error) {
		console.log(`[plugins] 保存授权失败：${error instanceof Error ? error.message : String(error)}`);
	}
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
				parsed = JSON.parse(rawText.replace(/^\uFEFF/, ""));
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
/**
* 插件请求编辑器操作（读文档 / 改代码）的超时。
* 比求解器短：这类操作要么立刻完成，要么说明渲染层有问题，
* 拖久了只会让插件和用户都卡着。
*/
var EDITOR_REQUEST_TIMEOUT_MS = 5e3;
/** 格式化可能处理大文件，而且可能等外部工具，给宽一点 */
var FORMAT_TIMEOUT_MS = 2e4;
/**
* 命令执行的超时。
* 命令可能触发一次编辑（快），也可能做点计算（稍慢），
* 但它是**用户主动点的**，拖太久只会让人以为卡死。
*/
var COMMAND_TIMEOUT_MS = 1e4;
var editorRequestSeq = 0;
function newEditorRequestId() {
	editorRequestSeq += 1;
	return `edit-${Date.now().toString(36)}-${editorRequestSeq}`;
}
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
	/**
	* 语言 id → 注册了格式化器的插件 id。
	* 同一个语言有多个插件注册时，**先注册的胜出**（和补全的合并语义不同 ——
	* 格式化只能有一个结果，合并两个格式化器没有意义）。
	*/
	formatters = /* @__PURE__ */ new Map();
	/** 命令 id → 注册它的插件 id */
	commands = /* @__PURE__ */ new Map();
	/**
	* 被用户停用的插件 id。
	* 停用 = 不激活沙箱、不参与补全/求解器/格式化/命令，
	* 等价于"装了这个插件但现在不想让它工作"。
	*/
	disabled = /* @__PURE__ */ new Set();
	idleTimer = null;
	initialized = false;
	constructor(options) {
		this.options = options;
	}
	async initialize() {
		if (this.initialized) return;
		this.initialized = true;
		const { records, broken } = await discoverPlugins(this.options.roots);
		const storedGrants = await loadPluginGrants();
		this.records.clear();
		for (const record of records) {
			record.granted = intersectGranted(record.manifest, storedGrants[record.manifest.id] ?? []);
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
		this.persistGrants();
		this.push();
		return this.list();
	}
	/**
	* 把当前授权写进 userData/plugin-grants.json。
	*
	* 不落盘的话"用户在设置里限制插件权限"这件事重启一次就白做了 ——
	* 而授权恰恰是最该记得住的偏好。
	*/
	persistGrants() {
		const map = {};
		for (const record of this.records.values()) if (record.granted.length > 0) map[record.manifest.id] = record.granted;
		this.grantWrite = (this.grantWrite ?? Promise.resolve()).then(() => savePluginGrants(map)).catch(() => {});
	}
	requirePermission(record, permission) {
		if (!record.granted.includes(permission)) throw new Error(`插件「${record.manifest.name}」没有 ${permission} 权限。请在插件面板里查看它申请的权限并授权。`);
	}
	async activate(id, reason = "manual") {
		if (!this.isEnabled(id)) return;
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
				} else if (kind === "formatter") {
					if (!this.formatters.has(value)) {
						this.formatters.set(value, id);
						console.log(`[plugin:${id}] 注册了 ${value} 的格式化器`);
					} else console.log(`[plugin:${id}] 语言 ${value} 已有格式化器（${this.formatters.get(value)}），忽略`);
				} else if (kind === "command") {
					const commandId = String(value);
					if (!this.commands.has(commandId)) {
						this.commands.set(commandId, id);
						console.log(`[plugin:${id}] 注册了命令 ${commandId}`);
					} else console.log(`[plugin:${id}] 命令 ${commandId} 已被 ${this.commands.get(commandId)} 注册，忽略`);
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
			if (!record.error) this.recordError(record, error instanceof Error ? error.message : String(error));
			else record.state = "error";
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
		const withSolvers = [...this.records.values()].filter((record) => this.isEnabled(record.manifest.id) && record.state !== "error" && (record.solvers.size > 0 || record.state !== "active"));
		await Promise.all(withSolvers.map((record) => this.activate(record.manifest.id, "onSolverPanel").catch((error) => {
			this.options.onPluginLog?.(record.manifest.id, `激活失败：${error instanceof Error ? error.message : String(error)}`);
		})));
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
	/** 哪些语言有格式化器（供渲染层决定「格式化」按钮是否可用） */
	listFormatters() {
		return Object.fromEntries(this.formatters);
	}
	/**
	* 用插件格式化一段文本。
	*
	* 找不到格式化器时返回 null —— 渲染层据此回退到 Monaco 自带的
	* （HTML / CSS / JSON / TypeScript 在 monaco-editor 里是有内置格式化器的）。
	*/
	async formatDocument(languageId, content) {
		const pluginId = this.formatters.get(languageId);
		if (!pluginId) return null;
		if (!this.isEnabled(pluginId)) return null;
		const record = this.records.get(pluginId);
		if (!record) return null;
		if (record.state === "error") throw new Error(`插件「${record.manifest.name}」处于错误状态：${record.error ?? "未知原因"}`);
		await this.activate(pluginId, `onLanguage:${languageId}`);
		const sandbox = this.sandboxes.get(pluginId);
		if (!sandbox?.alive) throw new Error(`插件「${record.manifest.name}」的沙箱没有启动成功`);
		const { result } = sandbox.request("formatDocument", {
			languageId,
			content: String(content ?? "").slice(0, 4e5)
		}, FORMAT_TIMEOUT_MS);
		try {
			const formatted = await result;
			if (typeof formatted !== "string") throw new Error("格式化器必须返回字符串");
			return formatted;
		} catch (error) {
			throw new Error(`格式化失败：${error instanceof Error ? error.message : String(error)}`);
		}
	}
	/**
	* 应用"停用哪些插件"。
	*
	* 停用立刻拆掉沙箱（不只是记个标记）：
	* 否则插件手里还握着已注册的求解器/格式化器，界面上看着"停用了"却还在工作，
	* 那是最容易让人困惑的状态。
	*/
	setDisabled(ids) {
		const next = new Set(ids.filter((id) => typeof id === "string" && id));
		for (const id of this.disabled) if (!next.has(id)) continue;
		for (const id of next) {
			if (this.disabled.has(id)) continue;
			this.teardownSandbox(id);
			for (const [language, pluginId] of [...this.formatters]) if (pluginId === id) this.formatters.delete(language);
			for (const [commandId, pluginId] of [...this.commands]) if (pluginId === id) this.commands.delete(commandId);
			const record = this.records.get(id);
			if (record) {
				record.solvers.clear();
				record.state = "inactive";
				record.sandboxAlive = false;
			}
		}
		this.disabled.clear();
		for (const id of next) this.disabled.add(id);
		this.push();
	}
	isEnabled(id) {
		return !this.disabled.has(id);
	}
	/**
	* 列出**已注册**的插件命令。
	*
	* 为什么只列已注册的：清单里的 contributes.commands 只是"声明"，
	* 插件真正调用 registerCommand 之后才可执行。
	* 把声明过但没实现的命令显示给用户，点下去只会报错 —— 不如不显示。
	*/
	listCommands() {
		const pending = [...this.records.values()].filter((record) => this.isEnabled(record.manifest.id) && record.state !== "error" && (record.manifest.contributes?.commands?.length ?? 0) > 0);
		for (const record of pending) this.activate(record.manifest.id, "onCommand").catch(() => {});
		const result = [];
		for (const [commandId, pluginId] of this.commands) {
			const record = this.records.get(pluginId);
			if (!record) continue;
			if (!this.isEnabled(pluginId)) continue;
			const declared = (record.manifest.contributes?.commands ?? []).find((command) => command.id === commandId);
			result.push({
				id: commandId,
				title: declared?.title ?? commandId,
				pluginId,
				pluginName: record.manifest.name
			});
		}
		return result.sort((a, b) => a.title.localeCompare(b.title));
	}
	/** 执行一个插件命令。返回给用户看的提示文字（可为空） */
	async executeCommand(commandId) {
		const pluginId = this.commands.get(commandId);
		if (!pluginId) throw new Error(`找不到命令 ${commandId}。可能它所属的插件没有启用。`);
		if (!this.isEnabled(pluginId)) throw new Error(`命令 ${commandId} 所属的插件已被停用`);
		const record = this.records.get(pluginId);
		if (!record) throw new Error("插件记录已失效");
		if (record.state === "error") throw new Error(`插件「${record.manifest.name}」处于错误状态：${record.error ?? "未知原因"}`);
		await this.activate(pluginId, "onCommand");
		const sandbox = this.sandboxes.get(pluginId);
		if (!sandbox?.alive) throw new Error(`插件「${record.manifest.name}」的沙箱没有启动成功`);
		const { result } = sandbox.request("runCommand", { commandId }, COMMAND_TIMEOUT_MS);
		try {
			const value = await result;
			return typeof value === "string" ? value : "";
		} catch (error) {
			throw new Error(`命令执行失败：${error instanceof Error ? error.message : String(error)}`);
		}
	}
	/** 哪些插件可能提供该语言的补全：已注册的 + 声明了 onLanguage 的 */
	providersFor(languageId) {
		const result = [];
		for (const record of this.records.values()) {
			if (!this.isEnabled(record.manifest.id)) continue;
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
			case "editor.getActiveDocument":
				this.requirePermission(record, "editor");
				return this.options.requestRenderer(newEditorRequestId(), { kind: "getActiveDocument" }, EDITOR_REQUEST_TIMEOUT_MS);
			case "editor.applyEdits": {
				this.requirePermission(record, "editor");
				const edits = sanitizeEdits(params.edits);
				if (edits.length === 0) throw new Error("applyEdits 需要至少一处有效编辑（行列都从 1 开始）");
				return this.options.requestRenderer(newEditorRequestId(), {
					kind: "applyEdits",
					path: String(params.path ?? ""),
					version: Number(params.version ?? -1),
					edits
				}, EDITOR_REQUEST_TIMEOUT_MS);
			}
			case "fs.readFile": {
				this.requirePermission(record, "fs:read");
				return await fsReadAny(resolveAnyPath(this.options.currentWorkspaceRoot(), params.path), params.encoding);
			}
			case "fs.writeFile": {
				this.requirePermission(record, "fs:write");
				return await fsWriteAny(resolveAnyPath(this.options.currentWorkspaceRoot(), params.path), params.content, params.encoding);
			}
			case "fs.readdir": {
				this.requirePermission(record, "fs:read");
				const target = resolveAnyPath(this.options.currentWorkspaceRoot(), params.path);
				const dirents = await (0, node_fs_promises.readdir)(target, { withFileTypes: true });
				return {
					path: target,
					truncated: dirents.length > MAX_DIR_ENTRIES,
					entries: dirents.slice(0, MAX_DIR_ENTRIES).map((dirent) => ({
						name: dirent.name,
						isFile: dirent.isFile(),
						isDirectory: dirent.isDirectory()
					}))
				};
			}
			case "fs.stat": {
				this.requirePermission(record, "fs:read");
				const target = resolveAnyPath(this.options.currentWorkspaceRoot(), params.path);
				try {
					const info = await (0, node_fs_promises.stat)(target);
					return {
						exists: true,
						path: target,
						isFile: info.isFile(),
						isDirectory: info.isDirectory(),
						size: info.size,
						mtimeMs: info.mtimeMs
					};
				} catch {
					return {
						exists: false,
						path: target
					};
				}
			}
			case "fs.mkdir": {
				this.requirePermission(record, "fs:write");
				const target = resolveAnyPath(this.options.currentWorkspaceRoot(), params.path);
				await assertWritable(target);
				await (0, node_fs_promises.mkdir)(target, { recursive: true });
				return {
					ok: true,
					path: target
				};
			}
			case "fs.rename": {
				this.requirePermission(record, "fs:write");
				const root = this.options.currentWorkspaceRoot();
				const from = resolveAnyPath(root, params.from);
				const to = resolveAnyPath(root, params.to);
				await assertWritable(from);
				await assertWritable(to);
				await (0, node_fs_promises.rename)(from, to);
				return {
					ok: true,
					from,
					to
				};
			}
			case "fs.unlink": {
				this.requirePermission(record, "fs:write");
				const target = resolveAnyPath(this.options.currentWorkspaceRoot(), params.path);
				await assertWritable(target);
				const info = await (0, node_fs_promises.stat)(target);
				if (info.isDirectory()) throw new Error("fs.unlink 只删文件；目录请逐个删里面的文件");
				await (0, node_fs_promises.unlink)(target);
				return {
					ok: true,
					path: target
				};
			}
			case "config.get": {
				this.requirePermission(record, "config");
				return await loadSettings(electron.app.getPath("userData"));
			}
			case "config.set": {
				this.requirePermission(record, "config");
				const rawPatch = params.patch;
				if (!rawPatch || typeof rawPatch !== "object" || Array.isArray(rawPatch)) throw new Error("config.set 需要一个 patch 对象");
				if (Object.prototype.hasOwnProperty.call(rawPatch, "disabledPlugins")) throw new Error("插件不能修改 disabledPlugins（否则可以给自己或别的插件提权）");
				const allowedKeys = new Set(Object.keys(DEFAULT_SETTINGS));
				const patch = {};
				const rejected = [];
				for (const key of Object.keys(rawPatch)) {
					if (key === "disabledPlugins") rejected.push(key);
					else if (allowedKeys.has(key)) patch[key] = rawPatch[key];
					else rejected.push(key);
				}
				const userData = electron.app.getPath("userData");
				const current = await loadSettings(userData);
				const saved = await saveSettings(userData, Object.assign({}, current, patch));
				sendToRenderer("settings:changed", saved);
				return {
					...saved,
					applied: Object.keys(patch),
					rejected
				};
			}
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
var cached$3;
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
	if (!force && cached$3 !== void 0) return cached$3;
	for (const candidate of CANDIDATES) {
		const found = tryCandidate(candidate);
		if (found) {
			cached$3 = found;
			return found;
		}
	}
	cached$3 = null;
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

/** 上次打开的文件夹记在这里（独立文件，和 settings.json 互不干扰） */
function lastWorkspaceFile() {
	return (0, node_path.join)(electron.app.getPath("userData"), "last-workspace.json");
}
function rememberWorkspace(directory) {
	try {
		const file = lastWorkspaceFile();
		if (!directory) {
			try {
				node_fs.unlinkSync(file);
			} catch {}
			return;
		}
		node_fs.writeFileSync(file, `${JSON.stringify({ path: (0, node_path.resolve)(directory) }, null, 2)}\n`, "utf8");
	} catch {}
}
/** 启动时调用：目录还在就恢复，不在（被删 / 被移动）就当没打开过 */
function restoreWorkspace() {
	try {
		const raw = JSON.parse(node_fs.readFileSync(lastWorkspaceFile(), "utf8").replace(/^\uFEFF/, ""));
		const dir = typeof raw?.path === "string" ? raw.path : "";
		if (!dir) return null;
		if (!node_fs.statSync(dir).isDirectory()) return null;
		workspaceRoot = (0, node_path.resolve)(dir);
		return workspaceRoot;
	} catch {
		return null;
	}
}
function currentWorkspace() {
	return {
		root: workspaceRoot,
		name: workspaceRoot ? (0, node_path.basename)(workspaceRoot) : ""
	};
}
/** 基准测试用：不经对话框直接设定工作区根目录 */
function setWorkspaceRoot(directory) {
	workspaceRoot = (0, node_path.resolve)(directory);
	rememberWorkspace(workspaceRoot);
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
	rememberWorkspace(workspaceRoot);
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
var cached$2 = null;
function loadToolchainConfig() {
	if (cached$2) return cached$2;
	try {
		const raw = (0, node_fs.readFileSync)(configPath(), "utf8");
		const parsed = JSON.parse(raw);
		cached$2 = typeof parsed === "object" && parsed !== null ? parsed : {};
	} catch {
		cached$2 = {};
	}
	return cached$2;
}
function saveToolchainConfig(update) {
	const next = {
		...loadToolchainConfig(),
		...update
	};
	cached$2 = next;
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
	cached$2 = {};
	try {
		(0, node_fs.writeFileSync)(configPath(), "{}", "utf8");
	} catch {}
	return cached$2;
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
		/*
		* WinLibs 的 UCRT + posix 线程 + SEH 异常版本，是现在 Windows 上最省事的
		* MinGW-w64 组合：支持 C++26、中文标识符、std::thread。
		*
		* 为什么列多个地址：GitHub Releases 在国内经常连不上或者几十 KB/s，
		* 而下载编译器是"装完就能用"的关键路径。第一个直连失败就自动换镜像，
		* 全都失败才报错 —— 用户不需要知道镜像这回事。
		*
		* 7z 比 zip 小一半多（106 MB vs 264 MB），所以选 7z，解压用随包的 7za.exe。
		*/
		urls: [
			"https://github.com/brechtsanders/winlibs_mingw/releases/download/16.2.0posix-23.1.3-14.0.0-ucrt-r3/winlibs-x86_64-posix-seh-gcc-16.2.0-mingw-w64ucrt-14.0.0-r3.7z",
			"https://ghfast.top/https://github.com/brechtsanders/winlibs_mingw/releases/download/16.2.0posix-23.1.3-14.0.0-ucrt-r3/winlibs-x86_64-posix-seh-gcc-16.2.0-mingw-w64ucrt-14.0.0-r3.7z",
			"https://gh-proxy.com/https://github.com/brechtsanders/winlibs_mingw/releases/download/16.2.0posix-23.1.3-14.0.0-ucrt-r3/winlibs-x86_64-posix-seh-gcc-16.2.0-mingw-w64ucrt-14.0.0-r3.7z",
			"https://mirror.ghproxy.com/https://github.com/brechtsanders/winlibs_mingw/releases/download/16.2.0posix-23.1.3-14.0.0-ucrt-r3/winlibs-x86_64-posix-seh-gcc-16.2.0-mingw-w64ucrt-14.0.0-r3.7z"
		],
		approximateBytes: 1065e5,
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
/**
* 单次连接的超时。
*
* 从 60 秒降到 15 秒是实测结论：国内直连 GitHub Releases 经常是 TCP 握手就挂住，
* 60 秒意味着用户要盯着"准备下载"干等一分钟才轮到镜像。
* 真正的慢速下载不受影响 —— 只要开始收数据，走的是下面的 STALL_TIMEOUT_MS 看门狗。
*/
var CONNECT_TIMEOUT_MS = 15e3;
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
				totalBytes: Number.isFinite(headerLength) && headerLength > 0 ? headerLength : null,
				request
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
/**
* 流式下载到文件，同时上报进度并支持取消。
*
* 还带一个"卡住就放弃"的看门狗：国内直连 GitHub 经常是**连上了但不给数据**，
* 连接超时管不到这种情况，用户会看着 0.0 MB 干等好几分钟。
* 30 秒收不到任何字节就主动断开，让上层换下一条线路。
*/
var STALL_TIMEOUT_MS = 3e4;
async function downloadTo(url, targetPath, toolId, context, label) {
	const { stream, totalBytes, request } = await openStream(url, context.signal);
	let receivedBytes = 0;
	let lastReportAt = 0;
	let lastDataAt = Date.now();
	let stalled = false;
	const watchdog = setInterval(() => {
		if (Date.now() - lastDataAt < STALL_TIMEOUT_MS) return;
		stalled = true;
		try {
			request.destroy(/* @__PURE__ */ new Error(`下载卡住（${STALL_TIMEOUT_MS / 1e3} 秒没有收到数据）`));
		} catch {}
	}, 5e3);
	stream.on("data", (chunk) => {
		receivedBytes += chunk.length;
		lastDataAt = Date.now();
		const now = Date.now();
		if (now - lastReportAt >= PROGRESS_INTERVAL_MS) {
			lastReportAt = now;
			report(context, toolId, "downloading", `${label} 下载中… ${(receivedBytes / 1024 / 1024).toFixed(1)} MB` + (totalBytes ? ` / ${(totalBytes / 1024 / 1024).toFixed(1)} MB` : ""), receivedBytes, totalBytes);
		}
	});
	try {
		await (0, node_stream_promises.pipeline)(stream, (0, node_fs.createWriteStream)(targetPath), { signal: context.signal });
	} catch (error) {
		if (stalled) throw new Error(`${label} 下载卡住，已切换线路（已收到 ${(receivedBytes / 1024 / 1024).toFixed(1)} MB）`);
		throw error;
	} finally {
		clearInterval(watchdog);
	}
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
		/*
		* 多线路下载：pkg.urls 里按顺序试，前一条失败（DNS / 超时 / 404 / 连接重置）
		* 就换下一条，全失败才把最后一条的错误抛给用户。
		* 这是国内下载 GitHub Releases 的必要设计 —— 直连经常几十 KB/s 甚至直接失败。
		*/
		const sources = Array.isArray(pkg.urls) && pkg.urls.length > 0 ? pkg.urls : [pkg.url];
		let lastError = null;
		for (let index = 0; index < sources.length; index += 1) {
			if (context.signal.aborted) throw new Error("已取消");
			try {
				const label = sources.length > 1 ? `${pkg.name}（线路 ${index + 1}/${sources.length}）` : pkg.name;
				await downloadTo(sources[index], archivePath, toolId, context, label);
				lastError = null;
				break;
			} catch (error) {
				if (context.signal.aborted) throw error;
				lastError = error;
				await (0, node_fs_promises.rm)(archivePath, { force: true }).catch(() => {});
				report(context, toolId, "resolving", `线路 ${index + 1} 不可用（${error instanceof Error ? error.message : String(error)}），正在换下一条…`);
			}
		}
		if (lastError) throw new Error(`所有下载线路都失败了：${lastError instanceof Error ? lastError.message : String(lastError)}`);
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
var cached$1 = null;
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
	if (!force && cached$1) return cached$1;
	const config = loadToolchainConfig();
	const startedAt = Date.now();
	cached$1 = detectTools({
		toolRoot: toolRoot(),
		bundledRoot: bundledToolRoot(),
		manualGccPath: isValidExecutable(config.manualGccPath) ? config.manualGccPath : void 0,
		manualPythonPath: isValidExecutable(config.manualPythonPath) ? config.manualPythonPath : void 0,
		preferredGccPath: config.preferredGccPath
	});
	console.log(`[toolchain] 探测完成：${Date.now() - startedAt} ms，找到 ${cached$1.compilers.length} 个编译器，选中 ${cached$1.selectedCompiler?.version ?? "（无）"}`);
	return cached$1;
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
			cached$1 = null;
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
		cached$1 = null;
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
		cached$1 = null;
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
		cached$1 = null;
		return {
			ok: true,
			tools: detect(true)
		};
	});
	electron.ipcMain.handle(TOOLCHAIN_CHANNELS.selectCandidate, (_event, executable) => {
		saveToolchainConfig({ preferredGccPath: executable });
		cached$1 = null;
		return {
			ok: true,
			tools: detect(true)
		};
	});
	electron.ipcMain.handle("toolchain:reset", () => {
		clearToolchainConfig();
		cached$1 = null;
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
		"# 按编译器版本挑 C++ 标准。",
		"# GCC 5 起才支持 C++17；Dev-Cpp 自带的 GCC 4.9 只到 C++14，",
		"# 硬写 17 会直接报 \"unrecognized command line option -std=c++17\"。",
		"if(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 5)",
		"    set(CMAKE_CXX_STANDARD 17)",
		"else()",
		"    set(CMAKE_CXX_STANDARD 14)",
		"endif()",
		"set(CMAKE_CXX_STANDARD_REQUIRED ON)",
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
function standardFlag(version) {
	const major = Number.parseInt((version || "0").split(".")[0] ?? "0", 10) || 0;
	/*
	* 按编译器大版本挑它**确实认识**的最高标准。
	* 挑高了会直接 "unrecognized command line option -std=c++26"，
	* 挑低了则白白浪费新编译器的能力，所以这张表要跟着 GCC 的发版节奏维护：
	*   GCC 15/16 → C++26      GCC 14 → C++23      GCC 11~13 → C++20
	*   GCC 5~10  → C++17      GCC 4  → C++14      更老 → C++11
	*/
	if (major >= 15) return "-std=c++26";
	if (major >= 14) return "-std=c++23";
	if (major >= 11) return "-std=c++20";
	if (major >= 5) return "-std=c++17";
	if (major >= 4) return "-std=c++14";
	return "-std=c++11";
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
	// 用户在「C++ 编译与链接参数」里配的额外参数（第三方库就靠这个）
	const buildConfig = loadBuildConfig();
	const userCflags = splitArgs(buildConfig.cflags);
	const userLdflags = splitArgs(buildConfig.ldflags);
	const flags = [buildConfig.cppStandard ? `-std=${buildConfig.cppStandard}` : standardFlag(compiler.version), ...userCflags];
	if (request.debug) flags.push("-g", "-O0");
	else flags.push(request.optimize === "none" ? "-O0" : `-${request.optimize}`);
	if (request.staticLink) flags.push("-static");
	// OI 相关：Windows 默认栈只有 1MB，DFS 递归十几万层就爆，
	// 而 OJ 上（Linux）是 8MB 起步 —— 不开大栈会测出"本地 RE、线上 AC"的假象。
	if (request.bigStack) flags.push("-Wl,--stack,268435456");
	// 运行时检查：STL 越界断言 + 有符号溢出/除零。UBSan 不是每台 MinGW 都有，
	// 链接失败时 oiBuild 会自动退回不带 sanitize 的版本。
	if (request.hardening) flags.push("-D_GLIBCXX_ASSERTIONS", "-Wall", "-Wextra");
	if (request.sanitize) flags.push("-fsanitize=undefined", "-fno-sanitize-recover=all");
	const runCompile = (withFlags) => runCommand(compiler.executable, [
		...withFlags,
		absoluteSource,
		"-o",
		executable,
		// 链接库要放在源文件后面，否则 GNU ld 会找不到符号
		...userLdflags
	], {
		cwd: sourceDirectory,
		env,
		timeoutMs: SINGLE_BUILD_TIMEOUT_MS
	});
	let result = await runCompile(flags);
	if (result.code !== 0 && standardUnsupported(result.output) && !buildConfig.cppStandard) {
		/*
		* 自动挑的标准被编译器拒绝了（版本号探测不准，或者是很老的 TDM-GCC）。
		* 沿着阶梯一路往下退，直到它能接受为止 —— 一次退到底会让 GCC 16 也用 C++11，
		* 那就等于把新编译器的能力全扔了。
		*/
		for (const fallback of ["c++23", "c++20", "c++17", "c++14", "c++11"]) {
			result = await runCompile(flags.map((flag) => flag.startsWith("-std=") ? `-std=${fallback}` : flag));
			if (result.code === 0) break;
			if (!standardUnsupported(result.output)) break;
		}
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
	const extraRunArgs = splitArgs(loadBuildConfig().runArgs).map((arg) => /[\s"]/.test(arg) ? `"${arg}"` : arg);
	const runSuffix = extraRunArgs.length ? ` ${extraRunArgs.join(" ")}` : "";
	env.SPARKLE_RUN_CMD = language === "python" ? `"${pythonExecutable || "python"}" "${absolute}"${runSuffix}` : `"${absolute}"${runSuffix}`;
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
		args = [(0, node_path.join)(root, request.executable), ...splitArgs(loadBuildConfig().runArgs)];
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
		args = splitArgs(loadBuildConfig().runArgs);
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
//#region src/shared/settings.ts
var DEFAULT_SETTINGS = {
	theme: "dark",
	editorFontSize: 14,
	uiFontSize: 13,
	disabledPlugins: []
};
// 新设置项：schema 里定义的默认值一并并进来（函数声明会被提升，这里可以调用）
Object.assign(DEFAULT_SETTINGS, __sparkleSettingsExtras({}));
var THEME_IDS = Object.keys({
	dark: {
		label: "深色（默认）",
		description: "对齐 VS Code Dark Modern 的取色",
		vars: {
			"--bg": "#1f1f1f",
			"--bg-elevated": "#181818",
			"--bg-panel": "#202020",
			"--border": "#2b2b2b",
			"--status-bg": "#181818",
			"--hover": "#2a2d2e",
			"--active": "#37373d"
		}
	},
	black: {
		label: "纯黑",
		description: "OLED 屏幕上更省电、对比更强",
		vars: {
			"--bg": "#000000",
			"--bg-elevated": "#0a0a0a",
			"--bg-panel": "#0d0d0d",
			"--border": "#1f1f1f",
			"--status-bg": "#0a0a0a",
			"--hover": "#1a1a1a",
			"--active": "#262626"
		}
	},
	navy: {
		label: "深蓝",
		description: "偏冷的深蓝底，长时间看眼睛舒服一些",
		vars: {
			"--bg": "#0d1b2a",
			"--bg-elevated": "#0a1622",
			"--bg-panel": "#11202f",
			"--border": "#1e3a52",
			"--status-bg": "#0a1622",
			"--hover": "#17324a",
			"--active": "#1f4463"
		}
	},
	warm: {
		label: "暖灰",
		description: "偏暖的深灰，像纸张的暗色调",
		vars: {
			"--bg": "#23201d",
			"--bg-elevated": "#1c1a17",
			"--bg-panel": "#272320",
			"--border": "#3a352f",
			"--status-bg": "#1c1a17",
			"--hover": "#302b26",
			"--active": "#3d372f"
		}
	}
});
var SETTINGS_CHANNELS = {
	get: "settings:get",
	set: "settings:set"
};
function clampFont(value, fallback) {
	const n = Number(value);
	if (!Number.isFinite(n)) return fallback;
	return Math.min(28, Math.max(10, Math.round(n)));
}
/**
* 把任何来源的设置洗成合法值。
* 单项非法只影响该项（回退默认），不会让整份设置作废 ——
* 用户改了字号却因为主题 id 写错导致全部重置，是很糟的体验。
*/
function sanitizeSettings(raw) {
	const input = raw ?? {};
	const theme = THEME_IDS.includes(input.theme) ? input.theme : DEFAULT_SETTINGS.theme;
	const disabledPlugins = [];
	if (Array.isArray(input.disabledPlugins)) for (const item of input.disabledPlugins) {
		if (typeof item !== "string") continue;
		const id = item.trim();
		if (id && !disabledPlugins.includes(id) && disabledPlugins.length < 200) disabledPlugins.push(id);
	}
	return Object.assign({
		theme,
		editorFontSize: clampFont(input.editorFontSize, DEFAULT_SETTINGS.editorFontSize),
		uiFontSize: clampFont(input.uiFontSize, DEFAULT_SETTINGS.uiFontSize),
		disabledPlugins
	}, __sparkleSettingsExtras(input));
}
//#endregion
//#region src/main/settings.ts
/**
* 设置的持久化。
*
* 存在 userData 下的 settings.json（不是工作区里）—— 主题、字号、停用哪些插件
* 都是"这台机器上的偏好"，跟具体项目无关。
*
* 读写策略：
*   · 读失败（不存在、损坏、无权限）一律回退默认 —— 设置文件坏掉不该让 IDE 打不开
*   · 写失败不抛给界面，只记录 —— 用户改字号时弹个错误框没有意义
*/
var cached = null;
function settingsPath(userDataPath) {
	return (0, node_path.join)(userDataPath, "settings.json");
}
async function loadSettings(userDataPath) {
	if (cached) return cached;
	try {
		const text = await (0, node_fs_promises.readFile)(settingsPath(userDataPath), "utf8");
		cached = sanitizeSettings(JSON.parse(text.replace(/^\uFEFF/, "")));
	} catch {
		cached = { ...DEFAULT_SETTINGS };
	}
	return cached;
}
/** 返回洗过之后的完整设置（调用方拿到的就是生效值） */
async function saveSettings(userDataPath, raw) {
	const next = sanitizeSettings(raw);
	cached = next;
	try {
		const path = settingsPath(userDataPath);
		await (0, node_fs_promises.mkdir)((0, node_path.dirname)(path), { recursive: true });
		await (0, node_fs_promises.writeFile)(path, `${JSON.stringify(next, null, 2)}\n`, "utf8");
	} catch (error) {
		console.log(`[settings] 写入失败（不影响本次使用）：${error instanceof Error ? error.message : String(error)}`);
	}
	return next;
}
//#endregion
//#region src/main/build-config.ts
/**
* 单文件编译 / 运行的额外参数。
*
* 存在 userData/build-config.json —— 这里存的是自由文本（一整行命令行参数），
* 没有枚举可校验，所以不塞进 settings.json。
*
* 目的：让「编译当前文件」能带上第三方库。比如 raylib（它必须在编译期链接）：
*   额外编译参数  -I C:/raylib/raylib/src
*   额外链接参数  -L C:/raylib/raylib/src -lraylib -lopengl32 -lgdi32 -lwinmm
*/
var BUILD_CONFIG_DEFAULT = {
	cppStandard: "",
	cflags: "",
	ldflags: "",
	runArgs: ""
};
var CPP_STANDARD_IDS = [
	"c++11",
	"c++14",
	"c++17",
	"c++20",
	"c++23",
	"c++26"
];
function buildConfigFile() {
	return (0, node_path.join)(electron.app.getPath("userData"), "build-config.json");
}
function oneLineText(value, max) {
	return typeof value === "string" ? value.replace(/[\r\n]+/g, " ").slice(0, max) : "";
}
function sanitizeBuildConfig(raw) {
	const input = raw && typeof raw === "object" ? raw : {};
	const std = typeof input.cppStandard === "string" ? input.cppStandard.trim() : "";
	return {
		cppStandard: CPP_STANDARD_IDS.includes(std) ? std : "",
		cflags: oneLineText(input.cflags, 2e3),
		ldflags: oneLineText(input.ldflags, 2e3),
		runArgs: oneLineText(input.runArgs, 1e3)
	};
}
function loadBuildConfig() {
	try {
		return sanitizeBuildConfig(JSON.parse(node_fs.readFileSync(buildConfigFile(), "utf8").replace(/^\uFEFF/, "")));
	} catch {
		return { ...BUILD_CONFIG_DEFAULT };
	}
}
function saveBuildConfig(raw) {
	const value = sanitizeBuildConfig(raw);
	try {
		node_fs.mkdirSync((0, node_path.dirname)(buildConfigFile()), { recursive: true });
		node_fs.writeFileSync(buildConfigFile(), `${JSON.stringify(value, null, 2)}\n`, "utf8");
	} catch {}
	return value;
}
/**
* 把 `-lraylib -L"C:/my lib"` 拆成 argv。
* spawn 用的是 shell:false，所以引号和空格必须自己处理，不能直接传一整串。
*/
function splitArgs(text) {
	const out = [];
	const source = String(text || "");
	let current = "";
	let quote = "";
	for (let i = 0; i < source.length; i += 1) {
		const ch = source[i];
		if (quote) {
			if (ch === quote) quote = "";
			else current += ch;
			continue;
		}
		if (ch === "\"" || ch === "'") {
			quote = ch;
			continue;
		}
		if (/\s/.test(ch)) {
			if (current) {
				out.push(current);
				current = "";
			}
			continue;
		}
		current += ch;
	}
	if (current) out.push(current);
	return out;
}
//#endregion
//#region src/main/ai.ts
/**
* AI 通道。
*
* 为什么请求要放在主进程：渲染层跑在 app:// 自定义源上，
* 直接 fetch 国内各家 API 会被 CORS 挡（它们基本都不返回 Access-Control-Allow-Origin）。
* 主进程用 Node 的 fetch 发请求，把流式增量通过 IPC 推回渲染层。
*
* 所有国内厂商都兼容 OpenAI 的 /chat/completions 形状，所以只写一条代码路径：
* 服务商只是"baseUrl + 默认模型"的一组预设，想接新家直接加一条即可。
*/
var AI_PROVIDERS = {
	deepseek: {
		label: "DeepSeek",
		baseUrl: "https://api.deepseek.com/v1",
		model: "deepseek-chat",
		hint: "platform.deepseek.com 申请 key"
	},
	qwen: {
		label: "通义千问（DashScope 兼容模式）",
		baseUrl: "https://dashscope.aliyuncs.com/compatible-mode/v1",
		model: "qwen-plus",
		hint: "bailian.console.aliyun.com 申请 key"
	},
	glm: {
		label: "智谱 GLM",
		baseUrl: "https://open.bigmodel.cn/api/paas/v4",
		model: "glm-4-flash",
		hint: "bigmodel.cn 申请 key，glm-4-flash 免费"
	},
	kimi: {
		label: "月之暗面 Kimi",
		baseUrl: "https://api.moonshot.cn/v1",
		model: "moonshot-v1-8k",
		hint: "platform.moonshot.cn 申请 key"
	},
	qianfan: {
		label: "百度千帆",
		baseUrl: "https://qianfan.baidubce.com/v2",
		model: "ernie-4.0-8k",
		hint: "console.bce.baidu.com 申请 key"
	},
	siliconflow: {
		label: "硅基流动 SiliconFlow",
		baseUrl: "https://api.siliconflow.cn/v1",
		model: "Qwen/Qwen2.5-Coder-32B-Instruct",
		hint: "siliconflow.cn 申请 key，有免费额度"
	},
	ollama: {
		label: "Ollama（本机，不用 key）",
		baseUrl: "http://127.0.0.1:11434/v1",
		model: "qwen2.5-coder:7b",
		hint: "本机先 ollama serve"
	},
	custom: {
		label: "自定义（OpenAI 兼容）",
		baseUrl: "",
		model: "",
		hint: "填任意 OpenAI 兼容的 baseUrl，例如 https://xxx/v1"
	}
};
var AI_DEFAULT = {
	provider: "deepseek",
	baseUrl: AI_PROVIDERS.deepseek.baseUrl,
	apiKey: "",
	model: AI_PROVIDERS.deepseek.model,
	temperature: .3,
	stream: true
};
var aiAborts = new Map();
function aiConfigFile() {
	return (0, node_path.join)(electron.app.getPath("userData"), "ai-config.json");
}
function sanitizeAiConfig(raw) {
	const input = raw && typeof raw === "object" ? raw : {};
	const provider = Object.prototype.hasOwnProperty.call(AI_PROVIDERS, input.provider) ? input.provider : AI_DEFAULT.provider;
	const preset = AI_PROVIDERS[provider];
	const temperature = Number(input.temperature);
	return {
		provider,
		baseUrl: typeof input.baseUrl === "string" && input.baseUrl.trim() ? input.baseUrl.trim().replace(/\/+$/, "") : preset.baseUrl,
		apiKey: typeof input.apiKey === "string" ? input.apiKey.trim().slice(0, 400) : "",
		model: typeof input.model === "string" && input.model.trim() ? input.model.trim().slice(0, 120) : preset.model,
		temperature: Number.isFinite(temperature) ? Math.min(2, Math.max(0, temperature)) : AI_DEFAULT.temperature,
		stream: input.stream !== false
	};
}
function loadAiConfig() {
	try {
		return sanitizeAiConfig(JSON.parse(node_fs.readFileSync(aiConfigFile(), "utf8").replace(/^\uFEFF/, "")));
	} catch {
		return { ...AI_DEFAULT };
	}
}
function saveAiConfig(raw) {
	const value = sanitizeAiConfig(raw);
	try {
		node_fs.mkdirSync((0, node_path.dirname)(aiConfigFile()), { recursive: true });
		node_fs.writeFileSync(aiConfigFile(), `${JSON.stringify(value, null, 2)}\n`, "utf8");
	} catch {}
	return value;
}
/** 流式输出时，把一帧一帧的增量推给界面 */
function aiEmitChunk(sender, payload) {
	try {
		if (sender && !sender.isDestroyed()) sender.send("ai:chunk", payload);
	} catch {}
}
/**
* 一次 chat/completions。
* 支持两种模式：流式（默认，边下边显示）和一次性（有些兼容实现不支持流式 tools）。
*/
async function aiChat(sender, request) {
	const cfg = loadAiConfig();
	const baseUrl = String(request && request.baseUrl || cfg.baseUrl || "").replace(/\/+$/, "");
	const model = String(request && request.model || cfg.model || "");
	if (!baseUrl) return {
		ok: false,
		error: "还没有配置接口地址。命令面板 → AI：设置接口与模型。"
	};
	if (!model) return {
		ok: false,
		error: "还没有配置模型名。命令面板 → AI：设置接口与模型。"
	};
	const apiKey = String(request && request.apiKey || cfg.apiKey || "").trim();
	const stream = request && request.stream === false ? false : cfg.stream !== false;
	const headers = { "content-type": "application/json" };
	if (apiKey) headers.authorization = `Bearer ${apiKey}`;
	const payload = {
		model,
		messages: Array.isArray(request?.messages) ? request.messages : [],
		stream,
		temperature: typeof request?.temperature === "number" ? request.temperature : cfg.temperature
	};
	if (Array.isArray(request?.tools) && request.tools.length > 0) {
		payload.tools = request.tools;
		payload.tool_choice = "auto";
	}
	if (typeof request?.maxTokens === "number" && request.maxTokens > 0) payload.max_tokens = Math.min(8192, request.maxTokens);
	const id = String(request?.id || `${Date.now()}`);
	const controller = new AbortController();
	aiAborts.set(id, controller);
	const timer = setTimeout(() => {
		try {
			controller.abort();
		} catch {}
	}, 18e4);
	try {
		const requestInit = (body) => ({
			method: "POST",
			headers,
			body: JSON.stringify(body),
			signal: controller.signal
		});
		let response = await fetch(`${baseUrl}/chat/completions`, requestInit(payload));
		if (response.status === 400 && payload.tools) {
			// 有的兼容实现（部分本地模型 / 老网关）不认识 tools，退一步按纯对话再试一次
			const plain = { ...payload };
			delete plain.tools;
			delete plain.tool_choice;
			response = await fetch(`${baseUrl}/chat/completions`, requestInit(plain));
		}
		if (!response.ok) {
			const text = await response.text().catch(() => "");
			return {
				ok: false,
				error: `HTTP ${response.status}：${String(text).slice(0, 600) || "没有响应内容"}`
			};
		}
		if (!stream) {
			const json = await response.json();
			const choice = json?.choices?.[0] ?? {};
			const message = choice.message ?? {};
			return {
				ok: true,
				content: typeof message.content === "string" ? message.content : "",
				toolCalls: Array.isArray(message.tool_calls) ? message.tool_calls : [],
				finishReason: choice.finish_reason ?? "",
				usage: json?.usage ?? null
			};
		}
		const reader = response.body.getReader();
		const decoder = new (require("node:string_decoder").StringDecoder)("utf8");
		let buffer = "";
		let content = "";
		let finishReason = "";
		const calls = [];
		let done = false;
		while (!done) {
			const { value, done: end } = await reader.read();
			if (end) break;
			buffer += decoder.write(Buffer.from(value));
			let cut;
			while ((cut = buffer.indexOf("\n\n")) >= 0) {
				const block = buffer.slice(0, cut);
				buffer = buffer.slice(cut + 2);
				for (const raw of block.split("\n")) {
					const line = raw.trim();
					if (!line.startsWith("data:")) continue;
					const data = line.slice(5).trim();
					if (data === "[DONE]") {
						done = true;
						continue;
					}
					let chunk;
					try {
						chunk = JSON.parse(data);
					} catch {
						continue;
					}
					const choice = chunk?.choices?.[0];
					if (!choice) continue;
					const delta = choice.delta ?? {};
					if (typeof delta.content === "string" && delta.content) {
						content += delta.content;
						aiEmitChunk(sender, { id, delta: delta.content });
					}
					if (Array.isArray(delta.tool_calls)) for (const item of delta.tool_calls) {
						const index = Number.isInteger(item.index) ? item.index : 0;
						if (!calls[index]) calls[index] = { id: "", type: "function", function: { name: "", arguments: "" } };
						if (item.id) calls[index].id = item.id;
						if (item.function?.name) calls[index].function.name += item.function.name;
						if (item.function?.arguments) calls[index].function.arguments += item.function.arguments;
					}
					if (choice.finish_reason) finishReason = choice.finish_reason;
				}
			}
		}
		return {
			ok: true,
			content,
			toolCalls: calls.filter(Boolean),
			finishReason,
			usage: null
		};
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		if (/abort/i.test(message)) return {
			ok: false,
			aborted: true,
			error: "已取消"
		};
		return {
			ok: false,
			error: `请求失败：${message}`
		};
	} finally {
		clearTimeout(timer);
		aiAborts.delete(id);
	}
}
//#endregion
//#region src/main/settings-schema.ts
/**
* 扩展设置项。
*
* 原版设置只有 theme / editorFontSize / uiFontSize / disabledPlugins，
* 这里补上"大多数编辑器都该有"的那些开关。两端（主进程与渲染层）
* 各留一份同样的 schema：谁负责洗值就用谁的，不跨进程传函数。
*
* 注意：这个函数是【函数声明】，会被提升，所以可以在 DEFAULT_SETTINGS
* 定义之前调用（DEFAULT_SETTINGS 初始化时就要用到默认值）。
*/
function __sparkleSettingSpecs() {
	return {
		editorFontFamily: {
			kind: "string",
			def: "Consolas, \"Courier New\", monospace",
			max: 200
		},
		editorLineHeight: {
			kind: "number",
			def: 1.45,
			min: 1.1,
			max: 2.2
		},
		tabSize: {
			kind: "enum",
			def: 4,
			values: [2, 4, 8]
		},
		insertSpaces: {
			kind: "bool",
			def: true
		},
		wordWrap: {
			kind: "enum",
			def: "off",
			values: ["off", "on", "bounded"]
		},
		wordWrapColumn: {
			kind: "number",
			def: 100,
			min: 40,
			max: 400
		},
		lineNumbers: {
			kind: "enum",
			def: "on",
			values: ["on", "off", "relative"]
		},
		minimap: {
			kind: "bool",
			def: true
		},
		renderWhitespace: {
			kind: "enum",
			def: "none",
			values: ["none", "boundary", "selection", "all"]
		},
		renderLineHighlight: {
			kind: "enum",
			def: "all",
			values: ["none", "line", "gutter", "all"]
		},
		cursorStyle: {
			kind: "enum",
			def: "line",
			values: ["line", "block", "underline"]
		},
		cursorBlinking: {
			kind: "enum",
			def: "smooth",
			values: ["blink", "smooth", "solid"]
		},
		bracketPairColorization: {
			kind: "bool",
			def: true
		},
		fontLigatures: {
			kind: "bool",
			def: false
		},
		smoothScrolling: {
			kind: "bool",
			def: true
		},
		autoSave: {
			kind: "enum",
			def: "off",
			values: ["off", "afterDelay", "onFocusChange"]
		},
		autoSaveDelay: {
			kind: "number",
			def: 1200,
			min: 300,
			max: 1e4
		},
		defaultLanguage: {
			kind: "enum",
			def: "",
			values: ["", "cpp", "python", "javascript", "typescript", "markdown", "json", "plaintext"]
		},
		aiLanguage: {
			kind: "enum",
			def: "auto",
			values: ["auto", "zh", "en"]
		},
		oiMode: {
			kind: "bool",
			def: false
		}
	};
}
/** 按 schema 把任意输入洗成一份合法的扩展设置 */
function __sparkleSettingsExtras(input) {
	const src = input && typeof input === "object" ? input : {};
	const specs = __sparkleSettingSpecs();
	const out = {};
	for (const key of Object.keys(specs)) {
		const spec = specs[key];
		const raw = src[key];
		let value = spec.def;
		if (spec.kind === "bool") {
			if (typeof raw === "boolean") value = raw;
		} else if (spec.kind === "enum") {
			if (spec.values.indexOf(raw) >= 0) value = raw;
		} else if (spec.kind === "number") {
			const n = Number(raw);
			if (Number.isFinite(n)) value = Math.min(spec.max, Math.max(spec.min, n));
		} else if (spec.kind === "string") {
			if (typeof raw === "string" && raw.trim()) value = raw.trim().slice(0, spec.max);
		}
		out[key] = value;
	}
	return out;
}
//#endregion
//#region src/main/oi.ts
/**
* OI 工作台的后端：本地测试、对拍、导题、Git。
*
* 几个设计原则：
*   · 测试走 stdin 喂数据，**不需要用户写 freopen** —— 这也是大多数 OJ 的做法；
*   · 导出题面/样例时只发一次请求，带用户自己在登录窗口里拿到的 Cookie，
*     不碰验证码、不模拟登录（验证码交给真实网页，我们复用它的会话）；
*   · 对拍是「生成器 + 正解 + 暴力」三个程序循环，发现差异立刻停并保留那份数据；
*   · Git 只做最小可用集（status / init / commit / log），不实现 diff 视图。
*/
var OI_SEP = "\\u0000-OI-\\u0000";
function oiNorm(text) {
	return String(text == null ? "" : text).replace(/\r\n/g, "\n").split("\n").map((line) => line.replace(/[ \t]+$/, "")).join("\n").replace(/\n+$/, "");
}
function oiSame(a, b) {
	return oiNorm(a) === oiNorm(b);
}
/** 跑一个可执行文件，把 stdin 喂进去 */
/**
* 子进程输出解码。
*
* 采样是 UTF-8，但 Windows 上 C++ 程序 printf("无解") 吐的是 GBK 字节 ——
* 直接按 UTF-8 解会得到一串替换字符，样例比对必然假 WA。
* 所以先试 UTF-8，出现替换字符再用 GBK 解一遍。
*/
function sparkleDecodeText(buffer) {
	if (!buffer || buffer.length === 0) return "";
	const utf8 = buffer.toString("utf8");
	if (utf8.indexOf("\uFFFD") < 0) return utf8;
	try {
		return new TextDecoder("gbk").decode(buffer);
	} catch {
		return utf8;
	}
}
/**
* 内存采样。
*
* Windows 上拿子进程的峰值内存没有轻量 API：Node 只暴露自己的，
* 而 PeakWorkingSet 只能在进程活着的时候读。于是按 150ms 轮询一次 tasklist，
* 取最大值。开销小（另一个进程，不吃被测程序的 CPU），代价是"采样峰值"，
* 可能比真实峰值低一点 —— 所以界面上标注为近似值。
*/
function sparkleStartMemorySampler(pid) {
	if (process.platform !== "win32" || !pid) return null;
	let peakKb = 0;
	let stopped = false;
	let timer = null;
	const probe = () => {
		if (stopped) return;
		(0, node_child_process.execFile)("tasklist", ["/FI", `PID eq ${pid}`, "/FO", "CSV", "/NH"], {
			windowsHide: true,
			encoding: "utf8",
			timeout: 3e3
		}, (error, stdout) => {
			if (error || !stdout) return;
			const found = /"([\d,.]+)\s*K"/.exec(stdout);
			if (!found) return;
			const kb = parseInt(found[1].replace(/[,.]/g, ""), 10);
			if (Number.isFinite(kb) && kb > peakKb) peakKb = kb;
		});
	};
	probe();
	timer = setInterval(probe, 150);
	return {
		stop() {
			stopped = true;
			if (timer) clearInterval(timer);
			timer = null;
			return peakKb;
		}
	};
}
function oiRunProgram(command, args, cwd, env, stdinText, timeoutMs) {
	return new Promise((resolve) => {
		// 输入走临时文件而不是管道：和 OJ 上的 freopen 行为一致，
		// 也避免几十 MB 的输入在管道里卡住事件循环。
		let inputFile = null;
		let inputFd = null;
		const cleanup = () => {
			if (inputFd != null) {
				try {
					(0, node_fs.closeSync)(inputFd);
				} catch {}
				inputFd = null;
			}
			if (inputFile) {
				try {
					(0, node_fs.unlinkSync)(inputFile);
				} catch {}
				inputFile = null;
			}
		};
		try {
			if (stdinText != null && stdinText !== "") {
				inputFile = (0, node_path.join)((0, node_os.tmpdir)(), `sparkle-oi-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.in`);
				(0, node_fs.writeFileSync)(inputFile, String(stdinText), "utf8");
				inputFd = (0, node_fs.openSync)(inputFile, "r");
			}
		} catch {
			cleanup();
		}
		let child;
		try {
			child = (0, node_child_process.spawn)(command, args, {
				cwd,
				env,
				windowsHide: true,
				shell: false,
				stdio: [inputFd != null ? inputFd : "ignore", "pipe", "pipe"]
			});
		} catch (error) {
			cleanup();
			resolve({
				code: null,
				output: "",
				stderr: String(error),
				ms: 0,
				timedOut: false,
				failed: true,
				memoryKb: 0
			});
			return;
		}
		const outChunks = [];
		const errChunks = [];
		let outBytes = 0;
		let errBytes = 0;
		let timedOut = false;
		const startedAt = Date.now();
		const sampler = sparkleStartMemorySampler(child.pid);
		const timer = setTimeout(() => {
			timedOut = true;
			try {
				child.kill();
			} catch {}
		}, Math.max(200, timeoutMs || 2e3));
		child.stdout.on("data", (chunk) => {
			if (outBytes >= 4e6) return;
			outChunks.push(chunk);
			outBytes += chunk.length;
		});
		child.stderr.on("data", (chunk) => {
			if (errBytes >= 4e5) return;
			errChunks.push(chunk);
			errBytes += chunk.length;
		});
		let settled = false;
		const finish = (code, failed) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			const memoryKb = sampler ? sampler.stop() : 0;
			cleanup();
			resolve({
				code,
				output: sparkleDecodeText(Buffer.concat(outChunks)),
				stderr: sparkleDecodeText(Buffer.concat(errChunks)),
				ms: Date.now() - startedAt,
				timedOut,
				failed,
				memoryKb
			});
		};
		child.on("error", (error) => {
			errChunks.push(Buffer.from(String(error), "utf8"));
			finish(null, true);
		});
		child.on("close", (code) => finish(code, false));
	});
}

function oiEnvFor(compiler) {
	const env = { ...process.env };
	delete env.ELECTRON_RUN_AS_NODE;
	if (compiler) prependPath(env, compiler.binDir);
	return env;
}
/** 编译一个源文件，返回 {ok, executable, error, output} */
/** 数一下编译输出里有几条 warning（用来在界面上提示"代码有味道"） */
function oiCountWarnings(text) {
	const found = String(text || "").match(/:\d+:\d+:\s*warning:/g);
	return found ? found.length : 0;
}
async function oiBuild(root, sourcePath, compiler, options) {
	if (/\.py$/i.test(sourcePath)) return {
		ok: true,
		executable: null,
		python: true,
		output: ""
	};
	const base = {
		path: sourcePath,
		optimize: "O2",
		debug: false,
		staticLink: false,
		bigStack: true,
		hardening: true
	};
	const wantSanitize = !!(options && options.sanitize);
	let build = await compileSingleFile(root, compiler, wantSanitize ? Object.assign({}, base, { sanitize: true }) : base);
	let sanitize = wantSanitize;
	let note = "";
	// UBSan 不是每台 MinGW 都带了 libubsan：链接不过时退回普通编译，
	// 别让用户以为自己的代码有问题。GLIBCXX 断言不受影响，仍然生效。
	if (wantSanitize && !build.ok) {
		const retry = await compileSingleFile(root, compiler, base);
		if (retry.ok) {
			build = retry;
			sanitize = false;
			note = "\n[提示] 这台机器的 GCC 没有 UBSan 运行库，已退回普通编译（STL 越界断言仍然生效）。";
		}
	}
	if (!build.ok) return {
		ok: false,
		error: build.friendlyError || "编译失败",
		output: build.output || "",
		warnings: oiCountWarnings(build.output)
	};
	return {
		ok: true,
		executable: build.executable,
		output: (build.output || "") + note,
		warnings: oiCountWarnings(build.output),
		sanitize
	};
}
/** 运行：Python 走解释器，C++ 走编译出来的 exe */
function oiCommandFor(root, sourcePath, built, compiler, pythonPath) {
	if (built && built.python) return {
		command: pythonPath || "python",
		args: [(0, node_path.join)(root, sourcePath)]
	};
	return {
		command: built.executable,
		args: []
	};
}
/** 一键测试：编译 + 逐组喂样例 + 比对 */
async function oiRunSamples(root, request) {
	const compiler = currentCompiler();
	const pythonPath = detect().find((tool) => tool.id === "python")?.path ?? "python";
	const built = await oiBuild(root, request.path, compiler, { sanitize: !!request.sanitize });
	if (!built.ok) return {
		ok: false,
		stage: "compile",
		error: built.error,
		output: built.output,
		warnings: built.warnings || 0,
		results: []
	};
	const cmd = oiCommandFor(root, request.path, built, compiler, pythonPath);
	const env = oiEnvFor(compiler);
	const cwd = (0, node_path.dirname)((0, node_path.join)(root, request.path));
	const timeLimit = Math.min(2e4, Math.max(200, Number(request.timeLimit) || 2e3));
	const memoryLimit = Math.max(0, Number(request.memoryLimit) || 0);
	const results = [];
	for (const item of request.cases || []) {
		const run = await oiRunProgram(cmd.command, cmd.args, cwd, env, item.input, timeLimit);
		const mle = memoryLimit > 0 && run.memoryKb > memoryLimit;
		const pass = !run.timedOut && !mle && run.code === 0 && oiSame(run.output, item.expected);
		results.push({
			name: item.name || "",
			pass,
			ms: run.ms,
			memoryKb: run.memoryKb,
			mle,
			timedOut: run.timedOut,
			code: run.code,
			got: String(run.output || "").slice(0, 8000),
			expected: String(item.expected || "").slice(0, 8000),
			stderr: String(run.stderr || "").slice(0, 4000)
		});
	}
	let cleaned = null;
	if (request.cleanup && built.executable) try {
		(0, node_fs.unlinkSync)(built.executable);
		cleaned = (0, node_path.basename)(built.executable);
	} catch {}
	return {
		ok: true,
		results,
		cleaned,
		warnings: built.warnings || 0,
		sanitize: built.sanitize !== false,
		timeLimit,
		memoryLimit,
		passed: results.filter((item) => item.pass).length,
		total: results.length
	};
}
/** 对拍：生成器 → 正解 / 暴力 → 比对，发现差异立即停 */
async function oiStress(root, request) {
	const compiler = currentCompiler();
	const pythonPath = detect().find((tool) => tool.id === "python")?.path ?? "python";
	const env = oiEnvFor(compiler);
	const built = {};
	for (const key of ["solution", "brute", "generator"]) {
		const sourcePath = request[key];
		if (!sourcePath) return {
			ok: false,
			error: `没有指定 ${key} 文件`
		};
		const one = await oiBuild(root, sourcePath, compiler);
		if (!one.ok) return {
			ok: false,
			error: `${(0, node_path.basename)(sourcePath)} 编译失败：${one.error}`,
			output: one.output
		};
		built[key] = Object.assign({ sourcePath }, one);
	}
	const cwd = (0, node_path.dirname)((0, node_path.join)(root, built.solution.sourcePath));
	const rounds = Math.min(500, Math.max(1, Number(request.rounds) || 100));
	const timeLimit = Math.min(1e4, Math.max(200, Number(request.timeLimit) || 2e3));
	const deadline = Date.now() + Math.min(6e4, Math.max(5e3, Number(request.totalMs) || 2e4));
	const runKey = async (key, stdin) => {
		const cmd = oiCommandFor(root, built[key].sourcePath, built[key], compiler, pythonPath);
		return oiRunProgram(cmd.command, cmd.args, cwd, env, stdin, timeLimit);
	};
	let done = 0;
	for (let round = 0; round < rounds; round += 1) {
		if (Date.now() > deadline) break;
		const gen = await runKey("generator", "");
		if (gen.timedOut || gen.failed) return {
			ok: false,
			error: "生成器运行失败",
			stderr: gen.stderr.slice(0, 2000),
			rounds: done
		};
		const input = gen.output;
		const [fast, slow] = await Promise.all([runKey("solution", input), runKey("brute", input)]);
		done += 1;
		const bad = fast.timedOut || fast.code !== 0 || slow.timedOut || slow.code !== 0 || !oiSame(fast.output, slow.output);
		if (bad) {
			// 反例必须落盘：对拍的输入是随机生成的，报一句"第 N 组不同"
			// 而不给数据，用户重跑一次大概率复现不出来。
			let hackDir = null;
			try {
				const base = (0, node_path.join)(cwd, "hack", `hack-${Date.now()}`);
				await (0, node_fs_promises.mkdir)(base, { recursive: true });
				await (0, node_fs_promises.writeFile)((0, node_path.join)(base, "data.in"), input, "utf8");
				await (0, node_fs_promises.writeFile)((0, node_path.join)(base, "sol.out"), fast.output, "utf8");
				await (0, node_fs_promises.writeFile)((0, node_path.join)(base, "brute.out"), slow.output, "utf8");
				await (0, node_fs_promises.writeFile)((0, node_path.join)(base, "about.txt"), [
					`第 ${done} 组数据不一致（${new Date().toLocaleString("zh-CN")}）`,
					`正解：${request.solution}`,
					`暴力：${request.brute}`,
					`生成器：${request.generator}`,
					`正解用时 ${fast.ms}ms，暴力用时 ${slow.ms}ms`,
					"",
					"复现：data.in 喂给任意一版程序即可。"
				].join("\n"), "utf8");
				hackDir = base;
			} catch {
				hackDir = null;
			}
			return {
			ok: true,
			found: true,
			rounds: done,
			hackDir,
			input: input.slice(0, 2e4),
			fast: {
				output: fast.output.slice(0, 2e4),
				ms: fast.ms,
				timedOut: fast.timedOut,
				code: fast.code,
				stderr: fast.stderr.slice(0, 2000)
			},
			slow: {
				output: slow.output.slice(0, 2e4),
				ms: slow.ms,
				timedOut: slow.timedOut,
				code: slow.code,
				stderr: slow.stderr.slice(0, 2000)
			}
			};
		}
	}
	return {
		ok: true,
		found: false,
		rounds: done
	};
}

/* ---------------- 导题 ---------------- */
var OJ_SITES = {
	luogu: {
		label: "洛谷",
		loginUrl: "https://www.luogu.com.cn/auth/login",
		origin: "https://www.luogu.com.cn",
		cookieUrl: "https://www.luogu.com.cn"
	},
	vjudge: {
		label: "VJudge",
		loginUrl: "https://vjudge.net/user/login",
		origin: "https://vjudge.net",
		cookieUrl: "https://vjudge.net"
	}
};
async function oiCookieHeader(siteKey) {
	const site = OJ_SITES[siteKey];
	if (!site) return "";
	try {
		const jar = await electron.session.defaultSession.cookies.get({ url: site.cookieUrl });
		return jar.map((cookie) => `${cookie.name}=${cookie.value}`).join("; ");
	} catch {
		return "";
	}
}
async function oiSessionState(siteKey) {
	// Cookie 只能说明"有会话"，不能说明"登录了"（三个站点未登录都会种 Cookie），
	// 所以状态一律以页面为准。
	return oiProbeLogin(siteKey);
}
/** 开一个真窗口让用户自己登录（验证码交给网页本身） */
/**
* 登录窗口。
*
* 判断"登录成功"只看**这个窗口里的 DOM 有没有 /logout 链接** —— 之前的做法是看 Cookie：
* 洛谷的 __client_id、AtCoder 的 REVEL_SESSION、CF 的 JSESSIONID **未登录时也会种上**，
* 于是没登录也报"已登录"。改成就地看页面，所见即所得。
*/
function oiOpenLogin(siteKey) {
	const site = OJ_SITES[siteKey];
	if (!site) return Promise.resolve({ ok: false, error: "不认识的站点" });
	return new Promise((resolve) => {
		const win = new electron.BrowserWindow({
			width: 980,
			height: 760,
			title: `登录 ${site.label}`,
			parent: mainWindow && !mainWindow.isDestroyed() ? mainWindow : void 0,
			modal: false,
			autoHideMenuBar: true,
			webPreferences: {
				sandbox: true,
				contextIsolation: true,
				nodeIntegration: false,
				spellcheck: false
			}
		});
		// Electron 默认 UA 带 Electron/xx，部分站点会直接拦；换成普通 Chrome
		try {
			win.webContents.setUserAgent(OI_UA);
		} catch {}
		let settled = false;
		let detected = false;
		let timer = null;
		const lookForLogout = async () => {
			if (win.isDestroyed()) return;
			try {
				const ok = await win.webContents.executeJavaScript(
					"!!document.querySelector('a[href=\"/logout\"], a[href=\"/user/logout\"], a[href*=\"/logout\"]')",
					true
				);
				if (ok && !detected) {
					detected = true;
					try {
						win.close();
					} catch {}
				}
			} catch {}
		};
		const schedule = () => {
			clearTimeout(timer);
			timer = setTimeout(lookForLogout, 1200);
		};
		win.webContents.on("did-navigate", schedule);
		win.webContents.on("did-navigate-in-page", schedule);
		win.webContents.on("did-finish-load", schedule);
		win.on("closed", async () => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			if (detected) {
				const header = await oiCookieHeader(siteKey);
				resolve({
					site: siteKey,
					loggedIn: true,
					verified: true,
					cookieCount: header ? header.split(";").filter(Boolean).length : 0
				});
				return;
			}
			resolve(await oiProbeLogin(siteKey));
		});
		win.loadURL(site.loginUrl);
	});
}

/**
* 真的去页面里确认登录状态（不看 Cookie）。
* 洛谷：contest/list 的 lentille 里 user 为 null 就是没登录
* AtCoder：/settings 未登录会跳登录页（带 password 输入框）
* Codeforces：Cloudflare 挡着，只能开隐藏窗口看首页有没有 /logout
*/
async function oiProbeLogin(siteKey) {
	const header = await oiCookieHeader(siteKey);
	const cookieCount = header ? header.split(";").filter(Boolean).length : 0;
	const base = {
		site: siteKey,
		cookieCount
	};
	if (siteKey === "codeforces") {
		const page = await oiBrowserHtml("https://codeforces.com/", { waitMs: 12000 });
		if (!page.ok) return {
			...base,
			loggedIn: false,
			verified: false,
			error: page.error
		};
		return {
			...base,
			loggedIn: /href="\/logout"/i.test(page.html),
			verified: true
		};
	}
	if (siteKey === "atcoder") {
		let html = "";
		let finalUrl = "";
		try {
			const res = await oiHttpFetch("https://atcoder.jp/settings", { accept: "text/html" });
			html = await res.text();
			finalUrl = String(res.url || "");
		} catch (error) {
			return {
				...base,
				loggedIn: false,
				verified: false,
				error: error instanceof Error ? error.message : String(error)
			};
		}
		return {
			...base,
			loggedIn: html.length > 2000 && !/name="password"/i.test(html) && !/\/login/i.test(finalUrl),
			verified: true
		};
	}
	if (siteKey !== "luogu") {
		// VJudge 之类没有可靠探针，只能退回 Cookie 判断，并标成"未验证"
		return {
			...base,
			loggedIn: Boolean(header),
			verified: false
		};
	}
	let html = "";
	try {
		const res = await oiHttpFetch("https://www.luogu.com.cn/contest/list?_contentOnly=1", {
			"x-luogu-type": "content-only",
			accept: "application/json, text/html"
		});
		html = await res.text();
	} catch (error) {
		return {
			...base,
			loggedIn: false,
			verified: false,
			error: error instanceof Error ? error.message : String(error)
		};
	}
	let payload = null;
	try {
		payload = JSON.parse(html);
	} catch {
		payload = oiExtractLentille(html) || oiExtractFeInjection(html);
	}
	const user = payload && payload.user;
	return {
		...base,
		loggedIn: Boolean(user && (user.uid || user.name)),
		verified: true
	};
}
function oiDecode(text) {
	return String(text || "").replace(/<[^>]+>/g, "").replace(/&nbsp;/g, " ").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&").replace(/&quot;/g, "\"").trim();
}
/**
* 统一的 HTTP 出口。
*
* **必须用 session.fetch**：洛谷对没有 Cookie 的请求会 302 回同一个地址
* （先种挑战 Cookie 再让你重来），Node 的 fetch 会跟随重定向但不带 Cookie，
* 于是在原地来回跳，最后报 redirect 失败 —— 这就是"一直抓取失败"的根因。
* session.fetch 走 Electron 自己的网络栈，自带 cookie jar，也跟着系统代理。
*/
var OI_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
async function oiHttpFetch(url, headers, requestInit) {
	const init = {
		...(requestInit || {}),
		headers: {
			"user-agent": OI_UA,
			accept: "application/json, text/html;q=0.9, */*;q=0.8",
			"accept-language": "zh-CN,zh;q=0.9",
			...headers
		},
		redirect: (requestInit && requestInit.redirect) || "follow"
	};
	try {
		const ses = electron.session.defaultSession;
		if (ses && typeof ses.fetch === "function") return await ses.fetch(url, init);
	} catch {}
	return fetch(url, init);
}
/** 从 HTML 里的 window._feInjection 里抠出数据（_contentOnly 失效时的兜底） */
function oiExtractFeInjection(html) {
	const m = /_feInjection\s*=\s*JSON\.parse\(decodeURIComponent\("([^"]+)"\)\)/.exec(String(html || ""));
	if (!m) return null;
	try {
		return JSON.parse(decodeURIComponent(m[1]));
	} catch {
		return null;
	}
}
/** 洛谷把数据塞在 <script id="lentille-context"> 里（2026 年的结构） */
function oiExtractLentille(html) {
	const m = /<script[^>]*id="lentille-context"[^>]*>([\s\S]*?)<\/script>/i.exec(String(html || ""));
	if (!m) return null;
	try {
		return JSON.parse(m[1]);
	} catch {
		return null;
	}
}
/** 三种可能的形状：data.problem / currentData.problem / problem */
function oiPickProblem(payload) {
	if (!payload) return null;
	if (payload.data && payload.data.problem) return payload.data.problem;
	if (payload.currentData && payload.currentData.problem) return payload.currentData.problem;
	if (payload.problem) return payload.problem;
	return null;
}
async function oiFetchLuogu(pid) {
	const url = `https://www.luogu.com.cn/problem/${encodeURIComponent(pid)}?_contentOnly=1`;
	let res;
	try {
		res = await oiHttpFetch(url, {
			"x-luogu-type": "content-only",
			accept: "application/json, text/html;q=0.9"
		});
	} catch (error) {
		return {
			ok: false,
			error: `连不上洛谷：${error instanceof Error ? error.message : String(error)}\n先点「登录 / 检查登录」，在打开的窗口里确认能打开洛谷。`
		};
	}
	if (!res.ok) return {
		ok: false,
		error: `洛谷返回 HTTP ${res.status}。题号对不对？（例如 P1001）`
	};
	const finalUrl = String(res.url || url);
	const text = await res.text();
	let payload = null;
	try {
		payload = JSON.parse(text);
	} catch {
		payload = oiExtractLentille(text) || oiExtractFeInjection(text);
	}
	const problem = oiPickProblem(payload);
	if (!problem) {
		const needLogin = /\/auth\/login/i.test(finalUrl);
		return {
			ok: false,
			error: needLogin ? "洛谷把请求转到了登录页：先点「登录 / 检查登录」登录一次，再回来抓。" : `没解析出题目数据（最终地址 ${finalUrl}，返回 ${text.length} 字符）。题号是否正确？比如 P1001。`
		};
	}
	let fields = problem.contenu || problem.content || {};
	if (typeof fields === "string") fields = { description: fields };
	const title = problem.name || problem.title || fields.name || pid;
	const raw = problem.samples || problem.sample || [];
	const samples = [];
	if (Array.isArray(raw)) for (const pair of raw) {
		if (Array.isArray(pair) && pair.length >= 2) samples.push({
			input: String(pair[0] == null ? "" : pair[0]),
			output: String(pair[1] == null ? "" : pair[1])
		});
	}
	const limits = problem.limits || {};
	const timeList = Array.isArray(limits.time) ? limits.time : [];
	const memoryList = Array.isArray(limits.memory) ? limits.memory : [];
	const timeLimitMs = Number(timeList[0]) > 0 ? Number(timeList[0]) : 1000;
	const memoryLimitKb = Number(memoryList[0]) > 0 ? Number(memoryList[0]) : 0;
	return {
		ok: true,
		title,
		pid: problem.pid || pid,
		background: fields.background || "",
		description: fields.description || "",
		inputFormat: fields.formatI || "",
		outputFormat: fields.formatO || "",
		hint: fields.hint || "",
		samples,
		timeLimitMs,
		memoryLimitKb,
		difficulty: problem.difficulty || 0
	};
}
async function oiFetchVjudge(pid) {
	const url = `https://www.vjudge.net/problem/${encodeURIComponent(pid)}`;
	let res;
	try {
		res = await oiHttpFetch(url, { accept: "text/html" });
	} catch (error) {
		return {
			ok: false,
			error: `连不上 VJudge：${error instanceof Error ? error.message : String(error)}`
		};
	}
	if (!res.ok) return {
		ok: false,
		error: `VJudge 返回 HTTP ${res.status}（题号形如 Luogu-P1001）`
	};
	const html = await res.text();
	const pres = [];
	const re = /<pre[^>]*>([\s\S]*?)<\/pre>/gi;
	let m;
	while ((m = re.exec(html)) && pres.length < 20) pres.push(oiDecode(m[1]));
	const samples = [];
	for (let k = 0; k + 1 < pres.length; k += 2) samples.push({
		input: pres[k],
		output: pres[k + 1]
	});
	const titleMatch = /<h[1-3][^>]*class="[^"]*title[^"]*"[^>]*>([\s\S]*?)<\/h[1-3]>/i.exec(html);
	if (!samples.length && /login|sign in/i.test(html.slice(0, 3000))) return {
		ok: false,
		error: "VJudge 需要登录才能看这题：先点「登录 / 检查登录」。"
	};
	return {
		ok: true,
		title: titleMatch ? oiDecode(titleMatch[1]) : pid,
		pid,
		content: "",
		description: "",
		samples
	};
}
async function oiFetchProblem(siteKey, pid) {
	try {
		if (siteKey === "vjudge") return await oiFetchVjudge(pid);
		if (siteKey === "codeforces") return await oiFetchCodeforces(pid);
		if (siteKey === "atcoder") return await oiFetchAtCoder(pid);
		return await oiFetchLuogu(pid);
	} catch (error) {
		return {
			ok: false,
			error: `抓取失败：${error instanceof Error ? error.message : String(error)}`
		};
	}
}
/** 把题目落成工作区文件：{dir}/{pid}.cpp + 1.in/1.out ... */
async function oiImportProblem(root, siteKey, pid, problem, dirOverride) {
	const safe = String(problem.pid || pid).replace(/[^A-Za-z0-9_.-]/g, "_");
	// 整场比赛导入时用「比赛ID/题号」两层目录；单题导入还是题号当目录
	const dirRelative = String(dirOverride || safe).replace(/\\/g, "/").replace(/^\/+|\/+$/g, "");
	const dirAbsolute = (0, node_path.join)(root, dirRelative);
	await (0, node_fs_promises.mkdir)(dirAbsolute, { recursive: true });
	const lines = [`# ${problem.title || safe}`, `来源：${OJ_SITES[siteKey] ? OJ_SITES[siteKey].label : siteKey} / ${problem.pid || pid}`];
	if (problem.timeLimitMs) lines.push(`时间限制：${problem.timeLimitMs} ms　内存限制：${problem.memoryLimitKb ? Math.round(problem.memoryLimitKb / 1024) + " MB" : "未提供"}`);
	lines.push("");
	for (const block of [problem.background, problem.description, problem.inputFormat && `### 输入格式\n${problem.inputFormat}`, problem.outputFormat && `### 输出格式\n${problem.outputFormat}`, problem.hint && `### 提示\n${problem.hint}`, problem.content]) {
		if (block) lines.push(String(block), "");
	}
	await (0, node_fs_promises.writeFile)((0, node_path.join)(dirAbsolute, "题目.md"), lines.join("\n"), "utf8");
	const samples = problem.samples || [];
	for (let i = 0; i < samples.length; i += 1) {
		await (0, node_fs_promises.writeFile)((0, node_path.join)(dirAbsolute, `${i + 1}.in`), samples[i].input, "utf8");
		await (0, node_fs_promises.writeFile)((0, node_path.join)(dirAbsolute, `${i + 1}.out`), samples[i].output, "utf8");
	}
	const codePath = (0, node_path.join)(dirAbsolute, `${safe}.cpp`);
	if (!(0, node_fs.existsSync)(codePath)) await (0, node_fs_promises.writeFile)(codePath, "#include <bits/stdc++.h>\nusing namespace std;\n\nint main() {\n\tios::sync_with_stdio(false);\n\tcin.tie(nullptr);\n\t\n\treturn 0;\n}\n", "utf8");
	return {
		ok: true,
		dir: dirRelative,
		code: `${dirRelative}/${safe}.cpp`,
		samples: samples.length,
		title: problem.title || safe,
		timeLimitMs: problem.timeLimitMs || 1000
	};
}

/* ================= OJ：在线提交 / 比赛 ================= */

// 新增两个站点（登录窗口、Cookie 读取都复用原来那套）
OJ_SITES.codeforces = {
	label: "Codeforces",
	loginUrl: "https://codeforces.com/enter",
	origin: "https://codeforces.com",
	cookieUrl: "https://codeforces.com"
};
OJ_SITES.atcoder = {
	label: "AtCoder",
	loginUrl: "https://atcoder.jp/login",
	origin: "https://atcoder.jp",
	cookieUrl: "https://atcoder.jp"
};

var OJ_LANGS = {
	luogu: [
		{ id: "5", label: "C++（洛谷默认）" },
		{ id: "11", label: "C++14" },
		{ id: "12", label: "C++17" },
		{ id: "27", label: "C++20" }
	],
	codeforces: [{ id: "auto", label: "自动（GNU G++）" }],
	atcoder: [{ id: "auto", label: "自动（最新 C++）" }]
};

var OJ_LUOGU_STATUS = {
	0: "等待评测",
	1: "评测中",
	2: "编译错误",
	3: "输出超限",
	4: "内存超限",
	5: "超时",
	6: "答案错误",
	7: "运行时错误",
	8: "未知错误",
	12: "通过",
	13: "不计分",
	14: "未通过",
	21: "Hack"
};

/** 把进度推给渲染层（导题、提交都能用） */
function oiEmitProgress(payload) {
	try {
		if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send("oi:progress", payload || {});
	} catch {}
}

async function oiCheckLogin(siteKey) {
	// 保留这个名字给 IPC 用，实现统一走页面探测
	return oiProbeLogin(siteKey);
}

/** 去掉标签、解码实体；不 trim，保留代码块里的空白 */
function oiStripTags(text) {
	return String(text || "").replace(/<[^>]+>/g, "");
}
function oiDecodeEntities(text) {
	return String(text || "").replace(/&nbsp;/g, " ").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, "\"").replace(/&#39;/g, "'").replace(/&copy;/g, "(c)").replace(/&amp;/g, "&");
}

/**
* 题面 HTML → Markdown。
* 只处理「题面里真会出现的」那几种标签，目标是让 题目.md 在 Markdown 预览里排得出来，
* 不追求完整还原（表格、图片只保留文字）。
*/
function oiHtmlToMarkdown(html) {
	let s = String(html || "").replace(/\r\n?/g, "\n");
	s = s.replace(/<(script|style)[\s\S]*?<\/\1>/gi, "");
	s = s.replace(/<div class="section-title">([\s\S]*?)<\/div>/gi, (m, body) => "\n### " + oiStripTags(body).trim() + "\n");
	s = s.replace(/<pre[^>]*>([\s\S]*?)<\/pre>/gi, (m, body) => "\n```\n" + oiStripTags(body).replace(/^\n+|\n+$/g, "") + "\n```\n");
	s = s.replace(/<h([1-6])[^>]*>([\s\S]*?)<\/h\1>/gi, (m, level, body) => "\n" + "#".repeat(Math.max(1, Math.min(6, Number(level)))) + " " + oiStripTags(body).replace(/\s+/g, " ").trim() + "\n");
	s = s.replace(/<li[^>]*>([\s\S]*?)<\/li>/gi, (m, body) => "\n- " + oiStripTags(body).replace(/\s+/g, " ").trim());
	s = s.replace(/<(strong|b)[^>]*>([\s\S]*?)<\/\1>/gi, (m, tag, body) => "**" + oiStripTags(body).trim() + "**");
	s = s.replace(/<(em|i)[^>]*>([\s\S]*?)<\/\1>/gi, (m, tag, body) => "*" + oiStripTags(body).trim() + "*");
	s = s.replace(/<code[^>]*>([\s\S]*?)<\/code>/gi, (m, body) => "`" + oiStripTags(body).trim() + "`");
	s = s.replace(/<var[^>]*>([\s\S]*?)<\/var>/gi, (m, body) => "`" + oiStripTags(body).trim() + "`");
	s = s.replace(/<br\s*\/?>/gi, "\n");
	s = s.replace(/<\/(p|div|section|blockquote|tr|table|ul|ol)>/gi, "\n\n");
	s = s.replace(/<[^>]+>/g, "");
	s = oiDecodeEntities(s);
	s = s.replace(/[ \t]+\n/g, "\n").replace(/\n{3,}/g, "\n\n");
	return s.trim();
}

/**
* 用隐藏窗口抓页面。
* Codeforces 前面挂着 Cloudflare，session.fetch 会拿到 "Just a moment..."，
* 只有真 Chromium 跑完 JS 挑战才能过 —— 所以这里开一个 show:false 的窗口，
* 等挑战自己过完再把 DOM 取出来。
*/
function oiBrowserHtml(url, options) {
	const opts = options || {};
	return new Promise((resolve) => {
		let win;
		try {
			win = new electron.BrowserWindow({
				show: false,
				width: 1280,
				height: 900,
				webPreferences: {
					sandbox: true,
					contextIsolation: true,
					nodeIntegration: false,
					spellcheck: false,
					backgroundThrottling: false,
					images: false
				}
			});
		} catch (error) {
			resolve({ ok: false, error: error instanceof Error ? error.message : String(error) });
			return;
		}
		let settled = false;
		const finish = (result) => {
			if (settled) return;
			settled = true;
			clearTimeout(deadline);
			try {
				win.destroy();
			} catch {}
			resolve(result);
		};
		const deadline = setTimeout(() => finish({ ok: false, error: "页面加载超时" }), opts.timeout || 45000);
		try {
			win.webContents.setUserAgent(OI_UA);
		} catch {}
		win.webContents.on("did-fail-load", (_event, _code, desc) => finish({ ok: false, error: "加载失败：" + desc }));
		win.webContents.on("did-finish-load", () => {
			const startedAt = Date.now();
			const budget = opts.waitMs || 15000;
			const read = async () => {
				if (settled) return;
				let html = "";
				try {
					html = String(await win.webContents.executeJavaScript("document.documentElement.outerHTML", true) || "");
				} catch {}
				const head = html.slice(0, 6000);
				const challenged = /Just a moment|cf-challenge|Checking your browser|Attention Required|Enable JavaScript and cookies/i.test(head) || html.length < 1200;
				if (!challenged || Date.now() - startedAt > budget) {
					finish({ ok: true, html, url: win.webContents.getURL() });
					return;
				}
				setTimeout(read, 1200);
			};
			setTimeout(read, 900);
		});
		try {
			win.loadURL(url);
		} catch (error) {
			finish({ ok: false, error: error instanceof Error ? error.message : String(error) });
		}
	});
}

function oiParseCfPid(raw) {
	const text = String(raw || "").trim().toUpperCase().replace(/[\s/_\-]/g, "");
	if (!text) return null;
	const m = /^([0-9]{1,6})([A-Z][0-9]{0,2})$/.exec(text);
	if (!m) return null;
	return { contestId: Number(m[1]), index: m[2] };
}

/* ---------------- 抓题：Codeforces / AtCoder ---------------- */

async function oiFetchCodeforces(pid) {
	const info = oiParseCfPid(pid);
	if (!info) return { ok: false, error: "Codeforces 题号写成 4A 或 2282A 这种形式" };
	const url = "https://codeforces.com/contest/" + info.contestId + "/problem/" + info.index;
	const page = await oiBrowserHtml(url, { waitMs: 20000 });
	if (!page.ok) return { ok: false, error: "打不开 Codeforces：" + page.error };
	const html = page.html;
	if (/Just a moment|cf-challenge|Checking your browser/i.test(html.slice(0, 8000))) return {
		ok: false,
		error: "Codeforces 的人机验证没通过：先点「登录 / 检查登录」，在打开的窗口里手动过一次验证，再回来导入。"
	};
	const titleMatch = /<div class="title">\s*([A-Za-z0-9]+)\s*\.\s*([\s\S]*?)<\/div>/.exec(html);
	const title = titleMatch ? oiDecodeEntities(oiStripTags(titleMatch[2])).trim() : info.contestId + info.index;
	const startAt = html.indexOf("<div class=\"problem-statement\">");
	const sampleAt = html.indexOf("<div class=\"sample-test\">");
	let stmt = startAt >= 0 ? html.slice(startAt, sampleAt > startAt ? sampleAt : void 0) : "";
	stmt = stmt.replace(/<div class="title">[\s\S]*?<\/div>/i, "").replace(/<div class="(time-limit|memory-limit|input-file|output-file)">[\s\S]*?<\/div>/gi, "");
	const samples = [];
	const sampleRe = /<div class="(input|output)">[\s\S]*?<pre[^>]*>([\s\S]*?)<\/pre>/gi;
	let match;
	while ((match = sampleRe.exec(html))) {
		const text = oiDecodeEntities(oiStripTags(match[2]));
		if (match[1] === "input") samples.push({ input: text + "\n", output: "" });
		else if (samples.length) samples[samples.length - 1].output = text + "\n";
	}
	const timeMatch = /time limit per test:\s*([\d.]+)\s*seconds?/i.exec(html);
	const memMatch = /memory limit per test:\s*([\d.]+)\s*megabytes?/i.exec(html);
	return {
		ok: true,
		title,
		pid: info.contestId + info.index,
		content: oiHtmlToMarkdown(stmt),
		description: "",
		samples,
		timeLimitMs: timeMatch ? Math.round(Number(timeMatch[1]) * 1000) : 2000,
		memoryLimitKb: memMatch ? Math.round(Number(memMatch[1]) * 1024) : 0
	};
}

async function oiFetchAtCoder(pid) {
	const taskId = String(pid || "").trim();
	const contestId = taskId.indexOf("_") >= 0 ? taskId.slice(0, taskId.lastIndexOf("_")) : "";
	if (!contestId) return { ok: false, error: "AtCoder 题号写成 abc400_a 这种形式" };
	const url = "https://atcoder.jp/contests/" + contestId + "/tasks/" + taskId + "?lang=en";
	let res;
	try {
		res = await oiHttpFetch(url, { accept: "text/html" });
	} catch (error) {
		return { ok: false, error: "连不上 AtCoder：" + (error instanceof Error ? error.message : String(error)) };
	}
	if (!res.ok) return { ok: false, error: "AtCoder 返回 HTTP " + res.status };
	const html = await res.text();
	const titleMatch = /<title>([^<]*)<\/title>/.exec(html);
	let title = titleMatch ? oiDecodeEntities(titleMatch[1]).trim() : taskId;
	title = title.replace(/\s*-\s*AtCoder\s*$/i, "").replace(/^[A-Z]+\s*-\s*/, "").trim();
	const enStart = html.indexOf("<span class=\"lang-en\">");
	const jaStart = html.indexOf("<span class=\"lang-ja\">");
	let body = enStart >= 0 ? html.slice(enStart) : html;
	// 题面只在 <div id="task-statement"> 里；两个语种块谁先谁后不固定，
	// 所以先看另一种语言块是不是在后面，否则退到分享按钮 / 页脚之前。
	let bodyEnd = -1;
	if (jaStart > enStart) bodyEnd = jaStart;
	else {
		const stops = [html.indexOf("<div class=\"a2a_kit", enStart), html.indexOf("<footer", enStart)].filter((at) => at > 0);
		if (stops.length) bodyEnd = Math.min.apply(null, stops);
	}
	if (bodyEnd > 0) body = html.slice(enStart, bodyEnd);
	const inputs = {};
	const outputs = {};
	const sampleRe = /<h3>\s*Sample (Input|Output)\s*([0-9]+)\s*<\/h3>\s*<pre[^>]*>([\s\S]*?)<\/pre>/gi;
	let match;
	while ((match = sampleRe.exec(body))) {
		const text = oiDecodeEntities(oiStripTags(match[3])).replace(/\r/g, "");
		const index = Number(match[2]);
		if (/input/i.test(match[1])) inputs[index] = text;
		else outputs[index] = text;
	}
	const samples = [];
	Object.keys(inputs).map(Number).sort((a, b) => a - b).forEach((index) => {
		if (outputs[index] == null) return;
		samples.push({ input: inputs[index] + "\n", output: outputs[index] + "\n" });
	});
	const statementHtml = body.replace(/<h3>\s*Sample (Input|Output)[\s\S]*?<\/section>/gi, "");
	const timeMatch = /Time Limit:\s*([\d.]+)\s*sec/i.exec(html);
	const memMatch = /Memory Limit:\s*([0-9]+)\s*(MiB|MB|GB)/i.exec(html);
	const memKb = memMatch ? ((/(GB)/i.test(memMatch[2]) ? Number(memMatch[1]) * 1024 * 1024 : Number(memMatch[1]))) : 0;
	return {
		ok: true,
		title,
		pid: taskId,
		content: oiHtmlToMarkdown(statementHtml),
		description: "",
		samples,
		timeLimitMs: timeMatch ? Math.round(Number(timeMatch[1]) * 1000) : 2000,
		memoryLimitKb: memKb
	};
}

/* ---------------- 提交 ---------------- */

/**
* 降级提交：把代码放进剪贴板，打开网页让用户自己粘贴 + 过验证码。
* 洛谷的风控（滑块/验证码）在接口层是过不去的，只能回到网页。
*/
function oiFallbackWindow(siteKey, pid, code, reason) {
	const site = OJ_SITES[siteKey];
	if (!site) return { ok: false, error: "不认识的站点" };
	try {
		electron.clipboard.writeText(String(code || ""));
	} catch {}
	const url = siteKey === "luogu" ? "https://www.luogu.com.cn/problem/" + encodeURIComponent(pid) : site.origin;
	try {
		const win = new electron.BrowserWindow({
			width: 1100,
			height: 860,
			title: "在网页里提交 · 代码已复制到剪贴板",
			parent: mainWindow && !mainWindow.isDestroyed() ? mainWindow : void 0,
			autoHideMenuBar: true,
			webPreferences: {
				sandbox: true,
				contextIsolation: true,
				nodeIntegration: false,
				spellcheck: false
			}
		});
		win.webContents.setUserAgent(OI_UA);
		win.loadURL(url);
	} catch (error) {
		return { ok: false, error: (reason ? reason + "；" : "") + "打开网页也失败了：" + (error instanceof Error ? error.message : String(error)) };
	}
	return {
		ok: true,
		site: siteKey,
		window: true,
		fallback: true,
		copied: true,
		message: "已把代码复制到剪贴板，并打开 " + site.label + " 的题目页：粘贴后自己点提交（验证码在网页里输）。" + (reason ? "\n原因：" + reason : "")
	};
}

async function oiSubmit(/* payload */ payload) {
	const site = String(payload && payload.site || "luogu");
	if (site === "luogu") return oiSubmitLuogu(payload);
	if (site === "atcoder") return oiSubmitAtCoder(payload);
	if (site === "codeforces") return oiSubmitCodeforcesWindow(payload);
	return { ok: false, error: "不认识的站点" };
}

async function oiSubmitLuogu(payload) {
	const pid = String(payload && payload.pid || "").trim();
	const code = String(payload && payload.code || "");
	if (!pid) return { ok: false, error: "先填题号" };
	if (!code.trim()) return { ok: false, error: "当前文件是空的，没东西可交" };
	let pageRes;
	try {
		pageRes = await oiHttpFetch("https://www.luogu.com.cn/problem/" + encodeURIComponent(pid), { accept: "text/html" });
	} catch (error) {
		return { ok: false, error: "连不上洛谷：" + (error instanceof Error ? error.message : String(error)) };
	}
	const html = await pageRes.text();
	if (/\/auth\/login/i.test(String(pageRes.url || "")) || /id="login-form"/.test(html)) return {
		ok: false,
		error: "洛谷还没登录：点「登录 / 检查登录」，在窗口里登录后再提交。"
	};
	const csrfMatch = /<meta name="csrf-token" content="([^"]+)"/.exec(html);
	const csrf = csrfMatch ? csrfMatch[1] : "";
	const lang = Number(payload && payload.lang) || 5;
	let res;
	try {
		res = await oiHttpFetch("https://www.luogu.com.cn/fe/api/problem/submit/" + encodeURIComponent(pid), {
			"content-type": "application/json",
			"x-csrf-token": csrf,
			"x-requested-with": "XMLHttpRequest",
			referer: "https://www.luogu.com.cn/problem/" + pid,
			origin: "https://www.luogu.com.cn",
			accept: "application/json"
		}, { method: "POST", body: JSON.stringify({ code, lang, enableO2: true }) });
	} catch (error) {
		return { ok: false, error: "提交请求失败：" + (error instanceof Error ? error.message : String(error)) };
	}
	const text = await res.text();
	let data = null;
	try {
		data = JSON.parse(text);
	} catch {}
	if (!data) return oiFallbackWindow("luogu", pid, code, "洛谷返回的不是 JSON（HTTP " + res.status + "），多半是登录失效或被风控拦了");
	if (data.errorCode || data.errorType) {
		const message = String(data.errorMessage || data.errorType || "");
		if (/Unlogin|未登录|尚未登录|not\s*logged/i.test(message)) return oiFallbackWindow("luogu", pid, code, "登录已失效");
		return oiFallbackWindow("luogu", pid, code, message);
	}
	const rid = data.rid || data.currentData && data.currentData.rid || data.data && data.data.rid;
	if (!rid) return { ok: false, error: "提交返回里没有记录号：" + text.slice(0, 160) };
	return { ok: true, site: "luogu", rid: String(rid), pid };
}

async function oiLuoguSubmission(rid) {
	if (!rid) return { ok: false, error: "缺少记录号" };
	const url = "https://www.luogu.com.cn/record/" + encodeURIComponent(rid) + "?_contentOnly=1";
	let res;
	try {
		res = await oiHttpFetch(url, { "x-luogu-type": "content-only", accept: "application/json, text/html" });
	} catch (error) {
		return { ok: false, error: "读取评测结果失败：" + (error instanceof Error ? error.message : String(error)) };
	}
	const text = await res.text();
	let payload = null;
	try {
		payload = JSON.parse(text);
	} catch {
		payload = oiExtractLentille(text) || oiExtractFeInjection(text);
	}
	const data = payload && (payload.currentData || payload.data) || {};
	const record = data.record || data.records && data.records.result && data.records.result[0];
	if (!record) return { ok: false, error: "读不到这条记录（可能登录失效了）" };
	const status = Number(record.status);
	const statusText = OJ_LUOGU_STATUS[status] || "状态 " + status;
	const accepted = status === 12;
	const done = status !== 0 && status !== 1;
	const compile = record.detail && record.detail.compileResult;
	const message = compile && !compile.success ? String(compile.stderr || compile.message || "").slice(0, 1200) : "";
	return {
		ok: true,
		done,
		accepted,
		status,
		statusText,
		score: record.score == null ? null : record.score,
		time: record.time == null ? null : record.time,
		memory: record.memory == null ? null : record.memory,
		compileError: message,
		url: "https://www.luogu.com.cn/record/" + rid
	};
}

async function oiSubmitAtCoder(payload) {
	const taskId = String(payload && payload.pid || "").trim();
	const code = String(payload && payload.code || "");
	if (!taskId || taskId.indexOf("_") < 0) return { ok: false, error: "AtCoder 题号写成 abc400_a 这种形式" };
	if (!code.trim()) return { ok: false, error: "当前文件是空的，没东西可交" };
	const contestId = taskId.slice(0, taskId.lastIndexOf("_"));
	const submitUrl = "https://atcoder.jp/contests/" + contestId + "/submit?taskScreenName=" + encodeURIComponent(taskId);
	let page;
	try {
		page = await oiHttpFetch(submitUrl, { accept: "text/html" });
	} catch (error) {
		return { ok: false, error: "连不上 AtCoder：" + (error instanceof Error ? error.message : String(error)) };
	}
	const html = await page.text();
	if (/\/login/i.test(String(page.url || ""))) return { ok: false, error: "AtCoder 还没登录：点「登录 / 检查登录」登录后再提交。" };
	const csrfMatch = /name="csrf_token"\s+value="([^"]+)"/.exec(html);
	if (!csrfMatch) return {
		ok: false,
		error: /sign in|log in|ログイン|ログインしてください/i.test(html)
			? "AtCoder 还没登录：点「登录 / 检查登录」登录后再提交。"
			: "没拿到 AtCoder 的 csrf_token（比赛可能已经结束，或者页面结构变了）"
	};
	const selectMatch = /<select[^>]*name="data\.LanguageId"[^>]*>([\s\S]*?)<\/select>/.exec(html);
	const languages = [];
	if (selectMatch) {
		const optionRe = /<option[^>]*value="([0-9]+)"[^>]*>([^<]+)<\/option>/gi;
		let option;
		while ((option = optionRe.exec(selectMatch[1]))) languages.push({ id: option[1], label: oiDecodeEntities(option[2]).trim() });
	}
	let langId = String(payload && payload.lang || "").trim();
	if (!/^[0-9]+$/.test(langId)) {
		const cpp = languages.filter((item) => /C\+\+/.test(item.label));
		const modern = cpp.filter((item) => /C\+\+\s*2[0-9]|GCC\s*1[2-9]/.test(item.label));
		langId = (modern[0] || cpp[0] || {}).id || "";
	}
	if (!langId) return { ok: false, error: "没在提交页里找到 C++ 语言选项" };
	const body = new URLSearchParams({
		csrf_token: csrfMatch[1],
		"data.TaskScreenName": taskId,
		"data.LanguageId": langId,
		sourceCode: code
	}).toString();
	let res;
	try {
		res = await oiHttpFetch(submitUrl, {
			"content-type": "application/x-www-form-urlencoded",
			referer: submitUrl,
			origin: "https://atcoder.jp",
			accept: "text/html"
		}, { method: "POST", body });
	} catch (error) {
		return { ok: false, error: "提交请求失败：" + (error instanceof Error ? error.message : String(error)) };
	}
	const finalUrl = String(res.url || "");
	const resHtml = await res.text();
	if (/\/submit(\?|$)/.test(finalUrl)) {
		const alertMatch = /<div class="alert alert-danger">([\s\S]*?)<\/div>/.exec(resHtml);
		return { ok: false, error: alertMatch ? oiDecodeEntities(oiStripTags(alertMatch[1])).trim() : "AtCoder 没有接受这次提交（未登录 / 比赛已结束 / 语言不对）" };
	}
	let sid = null;
	try {
		const meRes = await oiHttpFetch("https://atcoder.jp/contests/" + contestId + "/submissions/me", { accept: "text/html" });
		const meHtml = await meRes.text();
		const idMatch = new RegExp("/contests/" + contestId + "/submissions/([0-9]+)").exec(meHtml);
		if (idMatch) sid = idMatch[1];
	} catch {}
	return { ok: true, site: "atcoder", sid, contestId, taskId, langId };
}

async function oiAtCoderSubmission(contestId, sid) {
	if (!contestId || !sid) return { ok: false, error: "缺少提交记录号" };
	const url = "https://atcoder.jp/contests/" + contestId + "/submissions/" + sid;
	let res;
	try {
		res = await oiHttpFetch(url, { accept: "text/html" });
	} catch (error) {
		return { ok: false, error: "读取评测结果失败：" + (error instanceof Error ? error.message : String(error)) };
	}
	const html = await res.text();
	const statusMatch = /<td[^>]*id="judge-status"[^>]*>([\s\S]*?)<\/td>/.exec(html);
	const labelMatch = /<span class="label[^"]*">([^<]+)<\/span>/.exec(statusMatch ? statusMatch[1] : "");
	const raw = labelMatch ? oiDecodeEntities(labelMatch[1]).trim() : (statusMatch ? oiDecodeEntities(oiStripTags(statusMatch[1])).trim() : "");
	const statusText = raw || "等待评测";
	const pending = !raw || /WJ|Judging|Waiting|Queued/i.test(raw);
	const accepted = raw === "AC";
	const scoreMatch = /<td[^>]*id="judge-status"[^>]*>[\s\S]*?<\/td>\s*<td[^>]*class="text-right"[^>]*>([^<]*)<\/td>/.exec(html);
	return {
		ok: true,
		done: !pending,
		accepted,
		statusText,
		score: scoreMatch ? Number(scoreMatch[1]) || 0 : null,
		url
	};
}

/* ---- Codeforces：开窗口填代码，人机验证由用户点 ---- */

var oiCfWindow = null;
var oiCfTimers = [];

function oiCfStopTimers() {
	oiCfTimers.forEach((timer) => clearTimeout(timer));
	oiCfTimers = [];
}

function oiSubmitCodeforcesWindow(payload) {
	const info = oiParseCfPid(payload && payload.pid);
	if (!info) return { ok: false, error: "Codeforces 题号写成 4A 或 2282A 这种形式" };
	const code = String(payload && payload.code || "");
	if (!code.trim()) return { ok: false, error: "当前文件是空的，没东西可交" };
	const pidValue = String(info.index);
	const submitUrl = "https://codeforces.com/contest/" + info.contestId + "/submit";
	oiCfStopTimers();
	try {
		if (oiCfWindow && !oiCfWindow.isDestroyed()) oiCfWindow.close();
	} catch {}
	const win = new electron.BrowserWindow({
		width: 1000,
		height: 820,
		title: "Codeforces 提交 · 确认无误后点 Submit",
		parent: mainWindow && !mainWindow.isDestroyed() ? mainWindow : void 0,
		autoHideMenuBar: true,
		webPreferences: {
			sandbox: true,
			contextIsolation: true,
			nodeIntegration: false,
			spellcheck: false
		}
	});
	oiCfWindow = win;
	try {
		win.webContents.setUserAgent(OI_UA);
	} catch {}

	const fillScript = "(function(){" +
		"var code=" + JSON.stringify(code) + ";" +
		"var pid=" + JSON.stringify(pidValue) + ";" +
		"var ta=document.querySelector('textarea[name=\"source\"], textarea#source');" +
		"if(ta){ta.focus();ta.value=code;ta.dispatchEvent(new Event('input',{bubbles:true}));}" +
		"var pc=document.querySelector('input[name=\"submittedProblemCode\"], select[name=\"submittedProblemCode\"]');" +
		"if(pc){pc.value=pid;pc.dispatchEvent(new Event('input',{bubbles:true}));pc.dispatchEvent(new Event('change',{bubbles:true}));}" +
		"var sel=document.querySelector('select[name=\"programTypeId\"]');" +
		"var picked='';" +
		"if(sel){var opts=Array.prototype.slice.call(sel.options);" +
		"var num=function(o){var m=o.textContent.match(/[0-9]+/);return m?parseInt(m[0],10):0};" +
		"var cpp=opts.filter(function(o){return /GNU G[+][+]/.test(o.textContent)});" +
		"cpp.sort(function(a,b){return num(b)-num(a)});" +
		"if(cpp[0]){sel.value=cpp[0].value;sel.dispatchEvent(new Event('change',{bubbles:true}));picked=cpp[0].textContent.trim();}}" +
		"return {filled:!!(ta&&pc),pid:pc?pc.value:'',language:picked};" +
		"})()";

	const probeScript = "(function(){" +
		"var a=document.querySelector('a[href*=\"/submission/\"]');" +
		"var ok=document.querySelector('.alert-success');" +
		"return {href:a?a.getAttribute('href'):'',alert:ok?ok.textContent.trim():''};" +
		"})()";

	const state = { filled: false, polledUrl: "", done: false, warned: false };

	const schedule = (fn, delay) => {
		oiCfTimers.push(setTimeout(fn, delay));
	};

	const readVerdict = (url) => {
		if (win.isDestroyed() || state.done) return;
		win.webContents.executeJavaScript("(function(){var el=document.querySelector('span.verdict-accepted,span.verdict-rejected,span[class*=\"verdict\"]');return el?el.textContent.trim():''})()", true).then((verdict) => {
			if (win.isDestroyed() || state.done) return;
			const text = String(verdict || "").trim();
			if (!text || /TESTING|Running on test|Waiting|In queue|Pending/i.test(text)) {
				oiEmitProgress({ stage: "cf-judging", url, message: "已提交，正在评测…" });
				schedule(() => {
					if (!win.isDestroyed()) win.webContents.reload();
				}, 2500);
				schedule(() => readVerdict(url), 4000);
				return;
			}
			state.done = true;
			oiEmitProgress({
				stage: "cf-done",
				verdict: text,
				accepted: /Accepted|Pretests passed/i.test(text),
				url,
				message: "评测完成：" + text
			});
		}).catch(() => {});
	};

	const tick = () => {
		if (win.isDestroyed() || state.done) return;
		const href = win.webContents.getURL();
		if (/\/submission\//.test(href)) {
			if (state.polledUrl !== href) {
				state.polledUrl = href;
				readVerdict(href);
			}
			schedule(tick, 2000);
			return;
		}
		if (!/\/submit/.test(href)) {
			schedule(tick, 1500);
			return;
		}
		win.webContents.executeJavaScript(probeScript, true).then((probe) => {
			if (win.isDestroyed() || state.done) return;
			if (probe && probe.href) {
				state.polledUrl = "";
				oiEmitProgress({ stage: "cf-submitted", url: probe.href, message: "已提交：" + probe.href });
				try {
					win.loadURL(probe.href.indexOf("http") === 0 ? probe.href : "https://codeforces.com" + probe.href);
				} catch {}
				schedule(tick, 2500);
				return;
			}
			if (state.filled) {
				schedule(tick, 1800);
				return;
			}
			win.webContents.executeJavaScript(fillScript, true).then((result) => {
				if (win.isDestroyed() || state.done) return;
				if (!result || !result.filled) {
					if (!state.warned) {
						state.warned = true;
						oiEmitProgress({
							stage: "cf-need-action",
							message: "没找到提交表单：先在这个窗口里登录 Codeforces；登录后会自动把代码填进去。"
						});
					}
				} else {
					state.filled = true;
					oiEmitProgress({
						stage: "cf-filled",
						pid: pidValue,
						language: result.language,
						message: "代码已填好（" + (result.language || "默认语言") + "）。确认题号和语言后，点页面上的 Submit —— 人机验证也在这个窗口里过。"
					});
				}
				schedule(tick, 1800);
			}).catch(() => schedule(tick, 2000));
		}).catch(() => schedule(tick, 2000));
	};

	win.webContents.on("did-finish-load", () => {
		const href = win.webContents.getURL();
		if (/\/submit/.test(href)) state.filled = false;
		schedule(tick, 500);
	});
	win.on("closed", () => {
		oiCfStopTimers();
		oiCfWindow = null;
	});
	win.loadURL(submitUrl);
	return { ok: true, site: "codeforces", window: true, pid: info.contestId + info.index };
}

/**
* 比赛报名。
* 洛谷：POST /contest/{id}/join（csrf 从比赛页 meta 取）
* AtCoder：GET /contests/{id}/register 拿 csrf，再 POST 同一个地址
* Codeforces：报名页在 Cloudflare 后面，开窗口勾好"参加"，由用户点 Register
*/
async function oiContestJoin(siteKey, contestId) {
	const id = String(contestId || "").trim();
	if (!id) return { ok: false, error: "缺少比赛 ID" };
	if (siteKey === "codeforces") return oiCfRegisterWindow(id);
	if (siteKey === "atcoder") return oiAtCoderJoin(id);
	if (siteKey === "luogu") return oiLuoguJoin(id);
	return { ok: false, error: "不认识的站点" };
}

async function oiLuoguJoin(contestId) {
	const pageUrl = "https://www.luogu.com.cn/contest/" + encodeURIComponent(contestId);
	let res;
	try {
		res = await oiHttpFetch(pageUrl, { accept: "text/html" });
	} catch (error) {
		return { ok: false, error: "连不上洛谷：" + (error instanceof Error ? error.message : String(error)) };
	}
	const html = await res.text();
	let payload = null;
	try {
		payload = JSON.parse(html);
	} catch {
		payload = oiExtractLentille(html) || oiExtractFeInjection(html);
	}
	const user = payload && payload.user;
	if (!user || !(user.uid || user.name)) return {
		ok: false,
		needLogin: true,
		error: "洛谷还没登录：先点「登录 / 检查登录」。"
	};
	const data = payload && (payload.currentData || payload.data) || {};
	if (Number(data.joined) === 1) return {
		ok: true,
		already: true,
		message: "这场比赛你已经报名过了"
	};
	const contest = data.contest || {};
	if (contest.endTime && Number(contest.endTime) * 1000 < Date.now()) return {
		ok: false,
		error: "这场比赛已经结束了，报不上名"
	};
	const csrfMatch = /<meta name="csrf-token" content="([^"]+)"/.exec(html);
	let res2;
	try {
		res2 = await oiHttpFetch(pageUrl + "/join", {
			"content-type": "application/json",
			"x-csrf-token": csrfMatch ? csrfMatch[1] : "",
			"x-requested-with": "XMLHttpRequest",
			referer: pageUrl,
			origin: "https://www.luogu.com.cn",
			accept: "application/json"
		}, { method: "POST", body: "{}" });
	} catch (error) {
		return { ok: false, error: "报名请求失败：" + (error instanceof Error ? error.message : String(error)) };
	}
	const text = await res2.text();
	let out = null;
	try {
		out = JSON.parse(text);
	} catch {}
	if (!res2.ok || out && out.errorCode) {
		const message = out ? String(out.errorMessage || out.errorType || "") : "HTTP " + res2.status;
		if (/Unlogin|未登录|尚未登录|登录/i.test(message)) return {
			ok: false,
			needLogin: true,
			error: "洛谷登录已失效，重新登录一次再报名。"
		};
		return { ok: false, error: "报名失败：" + message };
	}
	return {
		ok: true,
		message: "报名成功"
	};
}

async function oiAtCoderJoin(contestId) {
	const url = "https://atcoder.jp/contests/" + encodeURIComponent(contestId) + "/register";
	let res;
	try {
		res = await oiHttpFetch(url, { accept: "text/html" });
	} catch (error) {
		return { ok: false, error: "连不上 AtCoder：" + (error instanceof Error ? error.message : String(error)) };
	}
	const html = await res.text();
	if (/name="password"/i.test(html) || /\/login/i.test(String(res.url || ""))) return {
		ok: false,
		needLogin: true,
		error: "AtCoder 还没登录：先点「登录 / 检查登录」。"
	};
	const csrfMatch = /name="csrf_token"\s+value="([^"]+)"/.exec(html);
	if (!csrfMatch) {
		if (/already|registered|登録済み/i.test(html)) return {
			ok: true,
			already: true,
			message: "这场比赛你已经报名过了"
		};
		return { ok: false, error: "没找到报名表单：这场比赛可能不需要报名，或者已经结束。" };
	}
	const body = new URLSearchParams({
		csrf_token: csrfMatch[1],
		agree: "true"
	}).toString();
	let res2;
	try {
		res2 = await oiHttpFetch(url, {
			"content-type": "application/x-www-form-urlencoded",
			referer: url,
			origin: "https://atcoder.jp",
			accept: "text/html"
		}, { method: "POST", body });
	} catch (error) {
		return { ok: false, error: "报名请求失败：" + (error instanceof Error ? error.message : String(error)) };
	}
	const finalUrl = String(res2.url || "");
	const out = await res2.text();
	if (/\/register(\?|$)/.test(finalUrl)) {
		const alertMatch = /<div class="alert alert-danger">([\s\S]*?)<\/div>/.exec(out);
		return {
			ok: false,
			error: alertMatch ? oiDecodeEntities(oiStripTags(alertMatch[1])).trim() : "报名没有成功（可能需要先同意条款，或比赛已结束）"
		};
	}
	return {
		ok: true,
		message: "报名成功"
	};
}

function oiCfRegisterWindow(contestId) {
	const url = "https://codeforces.com/contestRegistration/" + encodeURIComponent(contestId);
	try {
		if (oiCfWindow && !oiCfWindow.isDestroyed()) oiCfWindow.close();
	} catch {}
	const win = new electron.BrowserWindow({
		width: 900,
		height: 760,
		title: "Codeforces 报名 · 确认后点 Register",
		parent: mainWindow && !mainWindow.isDestroyed() ? mainWindow : void 0,
		autoHideMenuBar: true,
		webPreferences: {
			sandbox: true,
			contextIsolation: true,
			nodeIntegration: false,
			spellcheck: false
		}
	});
	oiCfWindow = win;
	try {
		win.webContents.setUserAgent(OI_UA);
	} catch {}
	const script = "(function(){" +
		"var box=document.querySelector('input[name=\"takePart\"]');" +
		"if(box&&!box.checked){box.checked=true;box.dispatchEvent(new Event('change',{bubbles:true}));}" +
		"var btn=document.querySelector('input[type=\"submit\"], button[type=\"submit\"], .submit');" +
		"return {hasBox:!!box,hasButton:!!btn,text:document.body?document.body.innerText.slice(0,120):''};" +
		"})()";
	win.webContents.on("did-finish-load", () => {
		if (win.isDestroyed()) return;
		if (/\/login|\/enter/i.test(win.webContents.getURL())) {
			oiEmitProgress({
				stage: "cf-register",
				ok: false,
				needLogin: true,
				message: "Codeforces 还没登录：在这个窗口里登录一次，登录后重新点「报名」。"
			});
			return;
		}
		win.webContents.executeJavaScript(script, true).then((result) => {
			oiEmitProgress({
				stage: "cf-register",
				ok: true,
				message: result && result.hasButton
					? "已勾选「参加」，确认信息后点页面上的 Register 完成报名。"
					: "已打开报名页：按页面提示完成报名（可能要过一次人机验证）。"
			});
		}).catch(() => {});
	});
	win.loadURL(url);
	return {
		ok: true,
		window: true,
		message: "已打开 Codeforces 报名页：勾选好参赛选项，点 Register 即可。"
	};
}

/* ---------------- 比赛列表 / 整场导入 ---------------- */

async function oiContestList(source) {
	if (source === "codeforces") {
		let res;
		try {
			res = await oiHttpFetch("https://codeforces.com/api/contest.list?gym=false", { accept: "application/json" });
		} catch (error) {
			return { ok: false, error: "连不上 Codeforces：" + (error instanceof Error ? error.message : String(error)) };
		}
		if (!res.ok) return { ok: false, error: "Codeforces 返回 HTTP " + res.status };
		const data = await res.json().catch(() => null);
		if (!data || data.status !== "OK") return { ok: false, error: "Codeforces 接口返回异常" };
		const contests = (data.result || []).filter((item) => item.phase === "BEFORE" || item.phase === "CODING").sort((a, b) => a.startTimeSeconds - b.startTimeSeconds).map((item) => ({
			id: String(item.id),
			name: item.name,
			startTime: item.startTimeSeconds * 1000,
			durationSec: item.durationSeconds,
			phase: item.phase
		}));
		return { ok: true, source, contests };
	}
	if (source === "atcoder") {
		let res;
		try {
			res = await oiHttpFetch("https://atcoder.jp/contests/", { accept: "text/html" });
		} catch (error) {
			return { ok: false, error: "连不上 AtCoder：" + (error instanceof Error ? error.message : String(error)) };
		}
		if (!res.ok) return { ok: false, error: "AtCoder 返回 HTTP " + res.status };
		const html = await res.text();
		const seen = {};
		const contests = [];
		const rowRe = /<tr>([\s\S]*?)<\/tr>/gi;
		let row;
		while ((row = rowRe.exec(html))) {
			const body = row[1];
			const link = /<a href="\/contests\/([A-Za-z0-9_-]+)">([^<]+)<\/a>/.exec(body);
			const time = /<time[^>]*>([^<]+)<\/time>/.exec(body);
			if (!link || !time) continue;
			const id = link[1];
			if (seen[id]) continue;
			const start = Date.parse(time[1].trim().replace(" ", "T"));
			if (!start || Number.isNaN(start)) continue;
			const duration = /<td class="text-center">([0-9]+):([0-9]+)<\/td>/.exec(body);
			const durationSec = duration ? (Number(duration[1]) * 60 + Number(duration[2])) * 60 : 0;
			seen[id] = true;
			contests.push({
				id,
				name: oiDecodeEntities(link[2]).trim(),
				startTime: start,
				durationSec,
				phase: start > Date.now() ? "BEFORE" : (durationSec && start + durationSec * 1000 > Date.now() ? "CODING" : "FINISHED")
			});
		}
		contests.sort((a, b) => a.startTime - b.startTime);
		const now = Date.now();
		return {
			ok: true,
			source,
			contests: contests.filter((item) => item.startTime > now - 36 * 3600 * 1000)
		};
	}
	// 洛谷
	let res;
	try {
		res = await oiHttpFetch("https://www.luogu.com.cn/contest/list?_contentOnly=1", {
			"x-luogu-type": "content-only",
			accept: "application/json, text/html"
		});
	} catch (error) {
		return { ok: false, error: "连不上洛谷：" + (error instanceof Error ? error.message : String(error)) };
	}
	const text = await res.text();
	let payload = null;
	try {
		payload = JSON.parse(text);
	} catch {
		payload = oiExtractLentille(text) || oiExtractFeInjection(text);
	}
	const data = payload && (payload.currentData || payload.data) || {};
	const list = data.contests && data.contests.result || [];
	const now = Date.now();
	return {
		ok: true,
		source: "luogu",
		contests: list.filter((item) => Number(item.endTime) * 1000 > now - 7 * 24 * 3600 * 1000).map((item) => ({
			id: String(item.id),
			name: item.name,
			startTime: Number(item.startTime) * 1000,
			durationSec: Number(item.endTime) - Number(item.startTime),
			phase: Number(item.startTime) * 1000 > now ? "BEFORE" : (Number(item.endTime) * 1000 > now ? "CODING" : "FINISHED")
		}))
	};
}

async function oiContestProblems(source, contestId) {
	if (!contestId) return { ok: false, error: "缺少比赛 ID" };
	if (source === "codeforces") {
		let apiError = "";
		try {
			const res = await oiHttpFetch("https://codeforces.com/api/contest.standings?contestId=" + encodeURIComponent(contestId) + "&from=1&count=1", { accept: "application/json" });
			const data = await res.json().catch(() => null);
			if (data && data.status === "OK" && data.result && data.result.problems) {
				return {
					ok: true,
					name: "Codeforces " + contestId,
					problems: data.result.problems.map((item) => ({
						pid: String(contestId) + item.index,
						title: item.name,
						index: item.index
					}))
				};
			}
			apiError = data && data.comment || "";
		} catch (error) {
			apiError = error instanceof Error ? error.message : String(error);
		}
		// CF 对非管理员只允许"无额外参数"的匿名 standings 请求，
		// 带 from/count 会被 400 拒掉（正在进行/已结束的比赛都一样），
		// 所以拿不到就退一步直接解析比赛页里的题目表格。
		const page = await oiBrowserHtml("https://codeforces.com/contest/" + encodeURIComponent(contestId), { waitMs: 15000 });
		if (!page.ok) return { ok: false, error: "打不开 Codeforces 比赛页：" + page.error };
		if (/Just a moment|cf-challenge/i.test(page.html.slice(0, 8000))) return {
			ok: false,
			error: "Codeforces 的人机验证没通过：先在登录窗口里过一次验证再导入。"
		};
		const found = {};
		// Codeforces 把题目标题包在 <!-- --> 注释里（<a href="..."><!-- -->标题<!-- --></a>），
		// 不去掉注释的话尖括号会直接把标题截断成空字符串。
		const clean = page.html.replace(/<!--[\s\S]*?-->/g, "");
		const linkRe = /<a[^>]+href="\/contest\/([0-9]+)\/problem\/([A-Za-z0-9]+)"[^>]*>([^<]*)<\/a>/g;
		let match;
		while ((match = linkRe.exec(clean))) {
			const index = String(match[2]).toUpperCase();
			const text = oiDecodeEntities(match[3]).trim();
			const prev = found[index];
			if (!prev || text.length > prev.title.length) found[index] = {
				index,
				title: text || index
			};
		}
		const problems = Object.keys(found).sort().map((index) => ({
			pid: String(contestId) + index,
			title: found[index].title,
			index
		}));
		if (!problems.length) return {
			ok: false,
			error: "没在比赛页里找到题目" + (apiError ? "（接口说：" + apiError + "）" : "（比赛可能还没开始）")
		};
		return { ok: true, name: "Codeforces " + contestId, problems };
	}
	if (source === "atcoder") {
		let res;
		try {
			res = await oiHttpFetch("https://atcoder.jp/contests/" + encodeURIComponent(contestId) + "/tasks", { accept: "text/html" });
		} catch (error) {
			return { ok: false, error: "连不上 AtCoder：" + (error instanceof Error ? error.message : String(error)) };
		}
		if (!res.ok) return { ok: false, error: "AtCoder 返回 HTTP " + res.status + "（比赛 ID 对不对？）" };
		const html = await res.text();
		// 每个题在表格里出现两次：一次是字母 A，一次是完整标题。
		// 之前只留第一个，结果标题全是 "A"、"B" —— 这里改成留更长的那个。
		const titles = {};
		const order = [];
		const linkRe = new RegExp("<a href=\"/contests/" + contestId + "/tasks/([A-Za-z0-9_-]+)\">([^<]+)</a>", "g");
		let match;
		while ((match = linkRe.exec(html))) {
			const pid = match[1];
			const text = oiDecodeEntities(match[2]).trim();
			if (!titles[pid]) {
				titles[pid] = text;
				order.push(pid);
			} else if (text.length > titles[pid].length) titles[pid] = text;
		}
		const problems = order.map((pid) => ({
			pid,
			title: titles[pid]
		}));
		if (!problems.length) return { ok: false, error: "没在这场比赛里找到题目" };
		return { ok: true, name: "AtCoder " + contestId, problems };
	}
	let res;
	try {
		res = await oiHttpFetch("https://www.luogu.com.cn/contest/" + encodeURIComponent(contestId) + "?_contentOnly=1", {
			"x-luogu-type": "content-only",
			accept: "application/json, text/html"
		});
	} catch (error) {
		return { ok: false, error: "连不上洛谷：" + (error instanceof Error ? error.message : String(error)) };
	}
	const text = await res.text();
	let payload = null;
	try {
		payload = JSON.parse(text);
	} catch {
		payload = oiExtractLentille(text) || oiExtractFeInjection(text);
	}
	const data = payload && (payload.currentData || payload.data) || {};
	const contest = data.contest || {};
	// 洛谷把题目放在 data.contestProblems 里（不是 contest.problems），
	// 结构是 [{no:"A", score:100, problem:{pid, name}}]
	const raw = data.contestProblems || contest.problems || [];
	if (!raw.length) return {
		ok: false,
		error: contest.startTime && Number(contest.startTime) * 1000 > Date.now()
			? "这场比赛还没开始：题目开赛后才会公开。"
			: "这场比赛没有可导入的题目（可能已下架，或题目还没公开）。"
	};
	return {
		ok: true,
		name: contest.name || ("洛谷比赛 " + contestId),
		problems: raw.map((item) => item.problem ? {
			pid: item.problem.pid,
			title: (item.no ? item.no + ". " : "") + (item.problem.name || item.problem.pid)
		} : {
			pid: item.pid,
			title: item.title || item.pid
		})
	};
}

async function oiImportContest(root, payload) {
	const source = String(payload && payload.site || "luogu");
	const contestId = String(payload && payload.contestId || "").trim();
	const list = await oiContestProblems(source, contestId);
	if (!list.ok) return list;
	const imported = [];
	const failed = [];
	for (let index = 0; index < list.problems.length; index += 1) {
		const item = list.problems[index];
		oiEmitProgress({
			stage: "import",
			site: source,
			contestId,
			index: index + 1,
			total: list.problems.length,
			pid: item.pid,
			title: item.title
		});
		const problem = await oiFetchProblem(source, item.pid);
		if (!problem.ok) {
			failed.push({ pid: item.pid, error: problem.error });
			continue;
		}
		try {
			const result = await oiImportProblem(root, source, item.pid, problem, contestId + "/" + item.pid);
			imported.push({ pid: item.pid, title: problem.title || item.title, dir: result.dir, code: result.code, samples: result.samples });
		} catch (error) {
			failed.push({ pid: item.pid, error: error instanceof Error ? error.message : String(error) });
		}
	}
	return { ok: true, site: source, contestId, name: list.name, imported, failed };
}

/* ---------------- Git ---------------- */
function oiExecFile(command, args, cwd) {
	return new Promise((resolve) => {
		(0, node_child_process).execFile(command, args, {
			cwd,
			windowsHide: true,
			maxBuffer: 4e6,
			encoding: "utf8"
		}, (error, stdout, stderr) => {
			resolve({
				ok: !error,
				code: error && typeof error.code === "number" ? error.code : error ? 1 : 0,
				stdout: String(stdout || ""),
				stderr: String(stderr || "") || (error ? String(error.message || error) : "")
			});
		});
	});
}
/** 会在等待输入凭据时挂住的操作，加点超时兜底 */
function oiExecFileTimed(command, args, cwd, timeoutMs) {
	return new Promise((resolve) => {
		(0, node_child_process).execFile(command, args, {
			cwd,
			windowsHide: true,
			maxBuffer: 4e6,
			encoding: "utf8",
			timeout: timeoutMs
		}, (error, stdout, stderr) => {
			resolve({
				ok: !error,
				timedOut: !!(error && error.killed),
				code: error && typeof error.code === "number" ? error.code : error ? 1 : 0,
				stdout: String(stdout || ""),
				stderr: String(stderr || "") || (error && !error.killed ? String(error.message || error) : "")
			});
		});
	});
}
async function oiGit(root, action, payload) {
	const probe = await oiExecFile("git", ["--version"], root);
	if (!probe.ok) return {
		ok: false,
		error: "没有找到 git。装一个 Git for Windows 就能用。"
	};
	const version = probe.stdout.trim();
	if (action === "status") {
		const branch = await oiExecFile("git", ["rev-parse", "--abbrev-ref", "HEAD"], root);
		const status = await oiExecFile("git", ["status", "--porcelain=v1"], root);
		const lines = status.stdout.split(/\r?\n/).filter(Boolean);
		return {
			ok: true,
			version,
			isRepo: branch.ok,
			branch: branch.ok ? branch.stdout.trim() : "",
			changes: lines.length,
			entries: lines.slice(0, 200).map((line) => ({
				code: line.slice(0, 2).trim(),
				path: line.slice(3)
			}))
		};
	}
	if (action === "init") {
		const init = await oiExecFile("git", ["init"], root);
		return init.ok ? {
			ok: true,
			message: "已初始化仓库"
		} : {
			ok: false,
			error: init.stderr || init.stdout
		};
	}
	if (action === "commit") {
		const message = String(payload && payload.message || "").trim();
		if (!message) return {
			ok: false,
			error: "提交信息不能为空"
		};
		const add = await oiExecFile("git", ["add", "-A"], root);
		if (!add.ok) return {
			ok: false,
			error: add.stderr || "git add 失败"
		};
		const commit = await oiExecFile("git", ["commit", "-m", message], root);
		return commit.ok ? {
			ok: true,
			message: "已提交"
		} : {
			ok: false,
			error: commit.stderr || commit.stdout || "提交失败（可能没有改动）"
		};
	}
	if (action === "log") {
		const log = await oiExecFile("git", ["log", "--oneline", "-n", "30"], root);
		return log.ok ? {
			ok: true,
			entries: log.stdout.split(/\r?\n/).filter(Boolean)
		} : {
			ok: false,
			error: log.stderr || "还没有任何提交"
		};
	}
	if (action === "pull" || action === "push" || action === "fetch") {
		const sub = action === "pull" ? ["pull", "--ff-only"] : action === "push" ? ["push"] : ["fetch", "--prune"];
		const r = await oiExecFileTimed("git", sub, root, 12e4);
		if (r.timedOut) return {
			ok: false,
			error: `git ${action} 超时（多半在等账号密码）。先在本机终端里跑一次把这个远端认下来，再回来重试。`
		};
		const out = (r.stdout || "").trim();
		const err = (r.stderr || "").trim();
		if (!r.ok) return {
			ok: false,
			error: err || out || `git ${action} 失败`
		};
		return {
			ok: true,
			message: [out, err].filter(Boolean).join("\n") || `git ${action} 完成`
		};
	}
	if (action === "branches") {
		const cur = await oiExecFile("git", ["rev-parse", "--abbrev-ref", "HEAD"], root);
		const list = await oiExecFile("git", ["branch", "--format=%(refname:short)"], root);
		return {
			ok: true,
			current: cur.ok ? cur.stdout.trim() : "",
			branches: list.ok ? list.stdout.split(/\r?\n/).map((x) => x.trim()).filter(Boolean) : []
		};
	}
	if (action === "checkout") {
		const name = String(payload && payload.branch || "").trim();
		if (!name || name.startsWith("-")) return {
			ok: false,
			error: "分支名不合法"
		};
		const r = await oiExecFile("git", ["checkout", name], root);
		return r.ok ? {
			ok: true,
			message: `已切到 ${name}`
		} : {
			ok: false,
			error: (r.stderr || r.stdout || "切换分支失败").trim()
		};
	}
	if (action === "diff") {
		const r = await oiExecFile("git", ["diff", "--stat"], root);
		return r.ok ? {
			ok: true,
			text: r.stdout.trim() || "工作区没有未暂存的改动"
		} : {
			ok: false,
			error: (r.stderr || "读不到 diff").trim()
		};
	}
	if (action === "remote") {
		const r = await oiExecFile("git", ["remote", "-v"], root);
		const text = r.stdout.trim();
		return {
			ok: r.ok,
			remotes: text,
			error: r.ok ? undefined : (r.stderr || "没有配置远端").trim()
		};
	}
	if (action === "version") return {
		ok: true,
		version
	};
	return {
		ok: false,
		error: "不认识的操作"
	};
}
//#endregion
//#region src/main/appearance.ts
/**
* 壁纸与透明度。
*
* 存在 userData/appearance.json（不是工作区里）——这是"这台机器的观感"，
* 而且壁纸要记绝对路径，不适合塞进 settings.json 那套只认枚举的 schema。
*/
var MEDIA_MIME = {
	".png": "image/png",
	".jpg": "image/jpeg",
	".jpeg": "image/jpeg",
	".webp": "image/webp",
	".gif": "image/gif",
	".bmp": "image/bmp",
	".avif": "image/avif",
	".svg": "image/svg+xml",
	".mp4": "video/mp4",
	".m4v": "video/mp4",
	".webm": "video/webm",
	".ogv": "video/ogg",
	".ogg": "video/ogg",
	".mov": "video/quicktime",
	".mkv": "video/x-matroska"
};
var IMAGE_EXTENSIONS = [".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".avif", ".svg"];
var VIDEO_EXTENSIONS = [".mp4", ".m4v", ".webm", ".ogv", ".ogg", ".mov", ".mkv"];
/** 太大的图转 base64 会把内存顶起来，超过这个就不转（视频一律走协议，不占内存） */
var MAX_WALLPAPER_BYTES = 24 * 1024 * 1024;
var APPEARANCE_DEFAULT = {
	/** 背景媒体文件的绝对路径（图片或视频） */
	mediaPath: null,
	/** "image" | "video" | null */
	mediaKind: null,
	/** 1.1.0 的旧字段，只为兼容旧配置，读取时会自动迁移到 mediaPath */
	wallpaper: null,
	/** 背景铺法：cover 铺满 / contain 完整显示 / fill 拉伸 / tile 平铺 */
	fit: "cover",
	/** 背景模糊半径（px） */
	blur: 0,
	/** 背景压暗程度 0~1 */
	dim: .18,
	/** 视频：循环 / 静音 / 播放倍速 */
	videoLoop: true,
	videoMuted: true,
	videoRate: 1,
	panelOpacity: .72,
	editorOpacity: 1,
	/** 主题预设 id（渲染层定义具体配色） */
	themeId: "default",
	/** 自定义强调色 #rrggbb，空字符串表示跟随主题 */
	accent: ""
};
function appearanceFile() {
	return (0, node_path.join)(electron.app.getPath("userData"), "appearance.json");
}
function clampUnit(value, fallback) {
	const n = Number(value);
	if (!Number.isFinite(n)) return fallback;
	return Math.min(1, Math.max(0, n));
}
function clampRange(value, fallback, min, max) {
	const n = Number(value);
	if (!Number.isFinite(n)) return fallback;
	return Math.min(max, Math.max(min, n));
}
function mediaKindFor(file) {
	if (!file) return null;
	const ext = (0, node_path.extname)(String(file)).toLowerCase();
	if (IMAGE_EXTENSIONS.includes(ext)) return "image";
	if (VIDEO_EXTENSIONS.includes(ext)) return "video";
	return null;
}
var FIT_VALUES = ["cover", "contain", "fill", "tile"];
var THEME_ID_PATTERN = /^[a-z0-9-]{1,32}$/;
function sanitizeAppearance(raw) {
	const input = raw && typeof raw === "object" ? raw : {};
	const rawPath = typeof input.mediaPath === "string" && input.mediaPath.trim() ? input.mediaPath : typeof input.wallpaper === "string" && input.wallpaper.trim() ? input.wallpaper : null;
	const mediaPath = rawPath ? (0, node_path.resolve)(rawPath) : null;
	const mediaKind = mediaPath ? mediaKindFor(mediaPath) ?? (input.mediaKind === "video" ? "video" : input.mediaKind === "image" ? "image" : null) : null;
	const accent = typeof input.accent === "string" && /^#[0-9a-fA-F]{6}$/.test(input.accent.trim()) ? input.accent.trim().toLowerCase() : "";
	return {
		mediaPath,
		mediaKind,
		wallpaper: mediaPath,
		fit: FIT_VALUES.includes(input.fit) ? input.fit : APPEARANCE_DEFAULT.fit,
		blur: Math.round(clampRange(input.blur, APPEARANCE_DEFAULT.blur, 0, 40)),
		dim: clampUnit(input.dim, APPEARANCE_DEFAULT.dim),
		videoLoop: input.videoLoop !== false,
		videoMuted: input.videoMuted !== false,
		videoRate: clampRange(input.videoRate, APPEARANCE_DEFAULT.videoRate, .25, 4),
		panelOpacity: clampUnit(input.panelOpacity, APPEARANCE_DEFAULT.panelOpacity),
		editorOpacity: clampUnit(input.editorOpacity, APPEARANCE_DEFAULT.editorOpacity),
		themeId: typeof input.themeId === "string" && THEME_ID_PATTERN.test(input.themeId) ? input.themeId : APPEARANCE_DEFAULT.themeId,
		accent
	};
}
function loadAppearance() {
	try {
		return sanitizeAppearance(JSON.parse(node_fs.readFileSync(appearanceFile(), "utf8").replace(/^\uFEFF/, "")));
	} catch {
		return { ...APPEARANCE_DEFAULT };
	}
}
function saveAppearance(raw) {
	const value = sanitizeAppearance(raw);
	try {
		node_fs.mkdirSync((0, node_path.dirname)(appearanceFile()), { recursive: true });
		node_fs.writeFileSync(appearanceFile(), `${JSON.stringify(value, null, 2)}\n`, "utf8");
	} catch {}
	return value;
}
/** 小图转 data URL：渲染层是 app:// 源，自己引用 file:// 会被安全策略拦掉 */
function wallpaperDataUrl(file) {
	if (!file) return null;
	try {
		const mime = MEDIA_MIME[(0, node_path.extname)(file).toLowerCase()];
		if (!mime || !mime.startsWith("image/")) return null;
		const info = node_fs.statSync(file);
		if (!info.isFile() || info.size > MAX_WALLPAPER_BYTES) return null;
		return `data:${mime};base64,${node_fs.readFileSync(file).toString("base64")}`;
	} catch {
		return null;
	}
}
/**
* 背景媒体的访问地址。
*
* 带上 mtime 当版本号：用户换了一张同名文件时浏览器缓存不会命中旧内容。
* 真正读盘在 sparkle-media 协议里，这里只给一个稳定的 URL。
*/
function mediaUrlFor(value) {
	if (!value.mediaPath) return null;
	try {
		const info = node_fs.statSync(value.mediaPath);
		if (!info.isFile()) return null;
		return `sparkle-media://local/current?v=${info.size}-${Math.round(info.mtimeMs)}`;
	} catch {
		return null;
	}
}
function appearancePayload() {
	const value = loadAppearance();
	const dataUrl = value.mediaKind === "image" ? wallpaperDataUrl(value.mediaPath) : null;
	const mediaUrl = mediaUrlFor(value);
	return {
		...value,
		dataUrl,
		mediaUrl,
		missing: Boolean(value.mediaPath) && !mediaUrl
	};
}
/**
* sparkle-media:// 的请求处理器。
*
* 安全边界：**只服务 appearance.json 里当前选中的那一个文件**。
* 不做 "把 URL 里的路径映射到磁盘" 这种事 —— 那样等于给渲染层开了任意读盘的后门。
*
* Range 是必须的：<video> 拖动进度条、边下边播全靠 206 响应，
* 一次性把 500 MB 读进内存既慢又容易把主进程拖垮。
*/
function serveMediaProtocol() {
	electron.session.defaultSession.protocol.handle("sparkle-media", async (request) => {
		const file = loadAppearance().mediaPath;
		if (!file) return new Response("Not Found", { status: 404 });
		let info;
		try {
			info = await node_fs_promises.stat(file);
		} catch {
			return new Response("Not Found", { status: 404 });
		}
		if (!info.isFile()) return new Response("Not Found", { status: 404 });
		const size = info.size;
		const mime = MEDIA_MIME[(0, node_path.extname)(file).toLowerCase()] ?? "application/octet-stream";
		const headers = {
			"content-type": mime,
			"accept-ranges": "bytes",
			"cache-control": "no-cache"
		};
		const rangeHeader = request.headers.get("range");
		const match = rangeHeader ? /^bytes=(\d*)-(\d*)$/.exec(rangeHeader.trim()) : null;
		if (match) {
			let start = match[1] === "" ? null : Number(match[1]);
			let end = match[2] === "" ? null : Number(match[2]);
			if (start === null && end !== null) {
				start = Math.max(0, size - end);
				end = size - 1;
			} else {
				if (start === null) start = 0;
				if (end === null || end >= size) end = size - 1;
			}
			if (!Number.isFinite(start) || !Number.isFinite(end) || start > end || start >= size) return new Response(null, {
				status: 416,
				headers: {
					...headers,
					"content-range": `bytes */${size}`
				}
			});
			return new Response(node_stream.Readable.toWeb(node_fs.createReadStream(file, {
				start,
				end
			})), {
				status: 206,
				headers: {
					...headers,
					"content-range": `bytes ${start}-${end}/${size}`,
					"content-length": String(end - start + 1)
				}
			});
		}
		return new Response(node_stream.Readable.toWeb(node_fs.createReadStream(file)), {
			status: 200,
			headers: {
				...headers,
				"content-length": String(size)
			}
		});
	});
}
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
var pendingEditorRequests = /* @__PURE__ */ new Map();
function requestRenderer(requestId, payload, timeoutMs) {
	return new Promise((resolve, reject) => {
		if (!mainWindow || mainWindow.isDestroyed()) {
			reject(/* @__PURE__ */ new Error("主窗口不可用，无法访问编辑器"));
			return;
		}
		const timer = setTimeout(() => {
			pendingEditorRequests.delete(requestId);
			reject(/* @__PURE__ */ new Error(`编辑器没有响应（${timeoutMs} ms 超时）`));
		}, timeoutMs);
		pendingEditorRequests.set(requestId, {
			resolve,
			reject,
			timer
		});
		mainWindow.webContents.send(PLUGIN_CHANNELS.editorRequest, {
			requestId,
			payload
		});
	});
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
			spellcheck: false,
			// 分屏里的 PDF / 网页预览用 <webview> 承载
			webviewTag: true
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
	/*
	* 分屏里的 <webview> 是内置的本地页面，不会自己传 preload 进来；
	* 这里仍然把 Node / preload 全部剥掉，并且只放行白名单协议，
	* 免得将来有人往 src 里塞奇怪的东西。
	*/
	window.webContents.on("will-attach-webview", (event, webPreferences, params) => {
		delete webPreferences.preload;
		webPreferences.nodeIntegration = false;
		webPreferences.nodeIntegrationInSubFrames = false;
		webPreferences.contextIsolation = true;
		webPreferences.webSecurity = true;
		const src = String(params.src || "");
		if (!/^(https?|file|app|about|data|blob):/i.test(src)) event.preventDefault();
	});
	window.webContents.on("did-attach-webview", (_event, contents) => {
		// 页面里 target=_blank 的链接交给系统浏览器，不在窗格里弹新窗口
		contents.setWindowOpenHandler(({ url }) => {
			if (/^https?:/i.test(url)) electron.shell.openExternal(url);
			return { action: "deny" };
		});
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
	serveMediaProtocol();
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
		},
		requestRenderer
	});
	await pluginHost.initialize();
	const bootSettings = await loadSettings(electron.app.getPath("userData"));
	pluginHost.setDisabled(bootSettings.disabledPlugins);
	mark("pluginsReady");
	electron.ipcMain.handle(RUN_CHANNELS.interpreter, () => interpreterInfo());
	electron.ipcMain.handle(RUN_CHANNELS.start, (_event, request) => runManager.start(request));
	electron.ipcMain.handle(RUN_CHANNELS.stop, (_event, runId) => runManager.stop(runId));
	electron.ipcMain.handle(FS_CHANNELS.openFolder, () => openFolder(mainWindow));
	electron.ipcMain.handle(FS_CHANNELS.currentWorkspace, () => currentWorkspace());
	electron.ipcMain.handle(FS_CHANNELS.readDirectory, (_event, path) => readDirectory(path ?? ""));
	electron.ipcMain.handle(FS_CHANNELS.readFile, (_event, path) => readFileContent(path));
	electron.ipcMain.handle(FS_CHANNELS.saveFile, (_event, path, content) => {
		saveFileCalls += 1;
		return saveFile(path, content);
	});

	/**
	* 另存为：给"还没打开文件夹就新建的未命名文件"用。
	* 选好位置后把工作区切到它所在的目录（和「打开文件」一致），
	* 这样存完立刻能在左边文件树里看到。
	*/
	electron.ipcMain.handle("fs:saveFileAs", async (_event, defaultName, content) => {
		const text = String(content ?? "");
		const options = {
			title: "另存为",
			defaultPath: String(defaultName || "未命名.txt"),
			filters: [{
				name: "C++ / Python 源文件",
				extensions: ["cpp", "cc", "cxx", "c", "py"]
			}, {
				name: "所有文件",
				extensions: ["*"]
			}]
		};
		const result = mainWindow ? await electron.dialog.showSaveDialog(mainWindow, options) : await electron.dialog.showSaveDialog(options);
		if (result.canceled || !result.filePath) return { ok: false, cancelled: true };
		const picked = (0, node_path.resolve)(result.filePath);
		const currentRoot = currentWorkspace().root;
		if (!(currentRoot ? picked.toLowerCase().startsWith(`${(0, node_path.resolve)(currentRoot).toLowerCase()}\\`) : false)) setWorkspaceRoot((0, node_path.dirname)(picked));
		const workspace = currentWorkspace();
		const base = (0, node_path.resolve)(workspace.root ?? (0, node_path.dirname)(picked));
		const relative = picked.slice(base.length).replace(/^[\\/]+/, "").replace(/\\/g, "/");
		await saveFile$1(base, relative || (0, node_path.basename)(picked), text);
		return {
			ok: true,
			workspace,
			path: relative,
			name: (0, node_path.basename)(picked)
		};
	});

	electron.ipcMain.handle(PLUGIN_CHANNELS.openFolder, async () => {
		const directory = (0, node_path.join)(electron.app.getPath("userData"), "plugins");
		await (0, node_fs_promises.mkdir)(directory, { recursive: true });
		electron.shell.openPath(directory);
		return directory;
	});
	electron.ipcMain.on(PLUGIN_CHANNELS.editorReply, (event, payload) => {
		if (!mainWindow || mainWindow.isDestroyed() || event.sender !== mainWindow.webContents) return;
		const reply = payload ?? {};
		const requestId = String(reply.requestId ?? "");
		const pending = pendingEditorRequests.get(requestId);
		if (!pending) return;
		clearTimeout(pending.timer);
		pendingEditorRequests.delete(requestId);
		if (reply.ok) pending.resolve(reply.result);
		else pending.reject(new Error(String(reply.error ?? "编辑器拒绝了这次操作")));
	});
	electron.ipcMain.handle(PLUGIN_CHANNELS.formatDocument, async (_event, request) => {
		if (!pluginHost) throw new Error("插件宿主尚未就绪");
		const params = request ?? {};
		return pluginHost.formatDocument(String(params.languageId ?? ""), String(params.content ?? ""));
	});
	electron.ipcMain.handle(PLUGIN_CHANNELS.listFormatters, () => {
		if (!pluginHost) return {};
		return pluginHost.listFormatters();
	});
	electron.ipcMain.handle(PLUGIN_CHANNELS.listCommands, () => {
		if (!pluginHost) return [];
		return pluginHost.listCommands();
	});
	electron.ipcMain.handle(PLUGIN_CHANNELS.executeCommand, async (_event, commandId) => {
		if (!pluginHost) throw new Error("插件宿主尚未就绪");
		return pluginHost.executeCommand(String(commandId ?? ""));
	});
	electron.ipcMain.handle("ai:loadConfig", () => ({
		config: loadAiConfig(),
		providers: AI_PROVIDERS
	}));
	electron.ipcMain.handle("ai:saveConfig", (_event, raw) => saveAiConfig(raw));
	electron.ipcMain.handle("ai:chat", (event, request) => aiChat(event.sender, request));
	electron.ipcMain.handle("ai:abort", (_event, id) => {
		const controller = aiAborts.get(String(id));
		if (!controller) return false;
		try {
			controller.abort();
		} catch {}
		return true;
	});
	electron.ipcMain.handle("oi:run", async (_event, request) => {
		try {
			const root = requireRoot();
			if (request && request.kind === "stress") return oiStress(root, request);
			return oiRunSamples(root, request);
		} catch (error) {
			return { ok: false, error: `先打开一个文件夹再测试（${error instanceof Error ? error.message : String(error)}）` };
		}
	});
	electron.ipcMain.handle("oi:oj", async (_event, payload) => {
		try {
			const action = payload?.action;
			const site = OJ_SITES[payload?.site] ? String(payload.site) : "luogu";
			if (action === "login") return oiOpenLogin(site);
			if (action === "status") return oiCheckLogin(site, payload?.verify);
			if (action === "fetch") return oiFetchProblem(site, String(payload?.pid || ""));
			if (action === "import") {
				const problem = await oiFetchProblem(site, String(payload?.pid || ""));
				if (!problem.ok) return problem;
				return await oiImportProblem(requireRoot(), site, String(payload?.pid || ""), problem);
			}
			return { ok: false, error: "不认识的操作" };
		} catch (error) {
			return { ok: false, error: `操作失败：${error instanceof Error ? error.message : String(error)}（导入题目需要先打开一个文件夹）` };
		}
	});
	electron.ipcMain.handle("oi:git", async (_event, payload) => {
		try {
			return await oiGit(requireRoot(), payload?.action, payload);
		} catch (error) {
			return { ok: false, error: `先打开一个文件夹再用 Git（${error instanceof Error ? error.message : String(error)}）` };
		}
	});
	/**
	* 读一张图片并转成 data URL。
	*
	* 题面里的图片是 `![](./1.png)` 这种相对路径，而界面跑在 app://bundle 下，
	* 相对路径解析不到工作区里的文件 —— 于是让主进程读出来塞成 data URL。
	* 只认图片扩展名，且限 8MB，免得被当成任意文件读取通道。
	*/
	electron.ipcMain.handle("fs:readImage", async (_event, rawPath) => {
		try {
			const target = resolveAnyPath(currentWorkspace().root, rawPath);
			const mime = {
				".png": "image/png",
				".jpg": "image/jpeg",
				".jpeg": "image/jpeg",
				".gif": "image/gif",
				".webp": "image/webp",
				".bmp": "image/bmp",
				".svg": "image/svg+xml",
				".avif": "image/avif"
			}[(0, node_path.extname)(target).toLowerCase()];
			if (!mime) return {
				ok: false,
				error: `不是图片文件：${target}`
			};
			const info = await (0, node_fs_promises.stat)(target);
			if (info.size > 8 * 1024 * 1024) return {
				ok: false,
				error: "图片超过 8MB，没有加载"
			};
			const data = await (0, node_fs_promises.readFile)(target);
			return {
				ok: true,
				dataUrl: `data:${mime};base64,${data.toString("base64")}`
			};
		} catch (error) {
			return {
				ok: false,
				error: error instanceof Error ? error.message : String(error)
			};
		}
	});
	electron.ipcMain.handle("git:exec", async (_event, payload) => {
		try {
			return await oiGit(requireRoot(), payload?.action, payload);
		} catch (error) {
			return { ok: false, error: `Git 面板需要先打开一个文件夹（${error instanceof Error ? error.message : String(error)}）` };
		}
	});
	electron.ipcMain.handle("oi:submit", async (_event, payload) => {
		try {
			return await oiSubmit(payload);
		} catch (error) {
			return { ok: false, error: `提交失败：${error instanceof Error ? error.message : String(error)}` };
		}
	});
	electron.ipcMain.handle("oi:submission", async (_event, payload) => {
		try {
			const site = String(payload?.site || "luogu");
			if (site === "luogu") return await oiLuoguSubmission(payload?.rid);
			if (site === "atcoder") return await oiAtCoderSubmission(payload?.contestId, payload?.sid);
			return { ok: false, error: "这个站点的结果要在它自己的窗口里看" };
		} catch (error) {
			return { ok: false, error: `读取评测结果失败：${error instanceof Error ? error.message : String(error)}` };
		}
	});
	electron.ipcMain.handle("oi:contests", async (_event, payload) => {
		try {
			return await oiContestList(String(payload?.source || "luogu"));
		} catch (error) {
			return { ok: false, error: `拉取比赛列表失败：${error instanceof Error ? error.message : String(error)}` };
		}
	});
	electron.ipcMain.handle("oi:join", async (_event, payload) => {
		try {
			return await oiContestJoin(String(payload?.site || "luogu"), String(payload?.contestId || ""));
		} catch (error) {
			return { ok: false, error: `报名失败：${error instanceof Error ? error.message : String(error)}` };
		}
	});
	electron.ipcMain.handle("oi:contestProblems", async (_event, payload) => {
		try {
			return await oiContestProblems(String(payload?.site || "luogu"), String(payload?.contestId || ""));
		} catch (error) {
			return { ok: false, error: `读取比赛题目失败：${error instanceof Error ? error.message : String(error)}` };
		}
	});
	electron.ipcMain.handle("oi:importContest", async (_event, payload) => {
		try {
			return await oiImportContest(requireRoot(), payload);
		} catch (error) {
			return { ok: false, error: `导入比赛失败（先打开一个文件夹）：${error instanceof Error ? error.message : String(error)}` };
		}
	});
	electron.ipcMain.handle("build:getConfig", () => loadBuildConfig());
	electron.ipcMain.handle("build:setConfig", (_event, raw) => saveBuildConfig(raw));
	electron.ipcMain.handle("appearance:load", () => appearancePayload());
	electron.ipcMain.handle("appearance:pick", async () => {
		const options = {
			title: "选择背景（图片或视频）",
			properties: ["openFile"],
			filters: [{
				name: "图片与视频",
				extensions: ["png", "jpg", "jpeg", "webp", "gif", "bmp", "avif", "svg", "mp4", "m4v", "webm", "ogv", "ogg", "mov", "mkv"]
			}, {
				name: "图片",
				extensions: ["png", "jpg", "jpeg", "webp", "gif", "bmp", "avif", "svg"]
			}, {
				name: "视频",
				extensions: ["mp4", "m4v", "webm", "ogv", "ogg", "mov", "mkv"]
			}, {
				name: "所有文件",
				extensions: ["*"]
			}]
		};
		const result = mainWindow ? await electron.dialog.showOpenDialog(mainWindow, options) : await electron.dialog.showOpenDialog(options);
		if (result.canceled || result.filePaths.length === 0) return { cancelled: true };
		const picked = result.filePaths[0];
		const current = loadAppearance();
		const kind = mediaKindFor(picked);
		if (!kind) return {
			...appearancePayload(),
			error: `不支持的文件类型：${(0, node_path.extname)(picked) || "（无扩展名）"}。图片支持 png / jpg / webp / gif / bmp / avif / svg，视频支持 mp4 / webm / ogv / mov / mkv。`
		};
		saveAppearance({
			...current,
			mediaPath: picked,
			mediaKind: kind,
			wallpaper: picked
		});
		return appearancePayload();
	});
	electron.ipcMain.handle("appearance:save", (_event, patch) => {
		const current = loadAppearance();
		const input = patch && typeof patch === "object" ? patch : {};
		saveAppearance({
			...current,
			...input,
			mediaPath: "mediaPath" in input ? input.mediaPath : current.mediaPath,
			mediaKind: "mediaKind" in input ? input.mediaKind : current.mediaKind
		});
		return appearancePayload();
	});
	electron.ipcMain.handle("appearance:clear", () => {
		saveAppearance({
			...loadAppearance(),
			mediaPath: null,
			mediaKind: null,
			wallpaper: null
		});
		return appearancePayload();
	});
	electron.ipcMain.handle(SETTINGS_CHANNELS.get, () => loadSettings(electron.app.getPath("userData")));
	electron.ipcMain.handle(SETTINGS_CHANNELS.set, async (_event, raw) => {
		const saved = await saveSettings(electron.app.getPath("userData"), raw);
		pluginHost?.setDisabled(saved.disabledPlugins);
		return saved;
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
	electron.ipcMain.handle(IDE_CHANNELS.compileFile, (_event, request) => compileSingleFile(requireRoot(), currentCompiler(), request));
	electron.ipcMain.handle(IDE_CHANNELS.runFile, (_event, request) => runExecutable(requireRoot(), currentCompiler(), detect().find((tool) => tool.id === "python")?.path ?? "python", request));
	electron.ipcMain.handle(IDE_CHANNELS.runInConsole, (_event, request) => runInConsole(requireRoot(), currentCompiler(), request.executable, request.language, detect().find((tool) => tool.id === "python")?.path ?? "python"));
	/**
	* 打开单个文件。
	*
	* 选的文件不在当前工作区里时，就把工作区切到它所在的目录再打开 ——
	* 用户点「打开文件」的意图就是"我要弄这个文件"，
	* 先让他自己去打开文件夹是多余的步骤。
	*/
	electron.ipcMain.handle(IDE_CHANNELS.openFileDialog, async (_event, kind) => {
		// kind === "pdf" 时只挑 PDF，别让对话框默认停在 cpp/cxx 上
		const wantsPdf = String(kind || "") === "pdf";
		const options = {
			title: wantsPdf ? "打开 PDF 文件" : "打开文件",
			properties: ["openFile"],
			filters: wantsPdf ? [{
				name: "PDF 文件",
				extensions: ["pdf"]
			}, {
				name: "所有文件",
				extensions: ["*"]
			}] : [{
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
	else restoreWorkspace();
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
					let undoRestored = false;
					let undoText = "";
					try {
						mainWindow.webContents.sendInputEvent({
							type: "keyDown",
							keyCode: "z",
							modifiers: ["control"]
						});
						mainWindow.webContents.sendInputEvent({
							type: "keyUp",
							keyCode: "z",
							modifiers: ["control"]
						});
						await new Promise((resolve) => setTimeout(resolve, 600));
						undoText = await readVisibleText();
						undoRestored = undoText.includes("ZZZ") === false;
					} catch {
						undoRestored = false;
					}
					recordDiagnostic("typingTest", {
						beforeLength: beforeText.length,
						afterLength: afterText.length,
						changed: beforeText !== afterText,
						containsZZZ: afterText.includes("ZZZ"),
						beforeSample: beforeText.slice(0, 120),
						afterSample: afterText.slice(0, 120),
						undoRestored,
						undoLength: undoText.length,
						undoStillHasZZZ: undoText.includes("ZZZ")
					});
				} catch (error) {
					recordDiagnostic("typingTest", { error: error instanceof Error ? error.message : String(error) });
				}
				try {
					recordDiagnostic("oiProbe", await mainWindow.webContents.executeJavaScript(`
                (async () => {
                  const api = window.sparkle?.plugin
                  if (!api) return { ok: false, reason: 'window.sparkle.plugin 不存在' }
                  const out = { ok: true }

                  // 先拿状态：这一步不触发激活，能立刻看出插件是不是 error
                  try {
                    const listed = await api.list()
                    out.plugins = (listed.plugins || []).map((p) => ({
                      id: p.id,
                      name: p.name,
                      state: p.state,
                      error: p.error || ''
                    }))
                  } catch (e) {
                    out.listPluginsError = String((e && e.message) || e)
                  }

                  // 再问求解器，最多等 6 秒
                  try {
                    const solvers = await Promise.race([
                      api.listSolvers(),
                      new Promise((_, reject) =>
                        setTimeout(() => reject(new Error('listSolvers 超时（6 秒）')), 6000)
                      )
                    ])
                    out.count = Array.isArray(solvers) ? solvers.length : -1
                    out.solvers = (solvers || []).slice(0, 15).map((s) => s.pluginId + ':' + s.id)
                    out.byPlugin = {}
                    for (const s of solvers || []) {
                      out.byPlugin[s.pluginId] = (out.byPlugin[s.pluginId] || 0) + 1
                    }
                  } catch (e) {
                    out.listError = String((e && e.message) || e)
                  }

                  const panel = document.querySelector('.oi-panel')
                  if (panel) {
                    out.panelText = panel.textContent.replace(/\\s+/g, ' ').trim().slice(0, 400)
                  }
                  return out
                })()
              `));
				} catch (error) {
					recordDiagnostic("oiProbe", {
						ok: false,
						reason: `探针失败：${error instanceof Error ? error.message : String(error)}`
					});
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
				if (process.env.SPARKLE_BENCH_FORMAT === "1") try {
					const beforeFormat = await mainWindow.webContents.executeJavaScript(`
                  (async () => {
                    const out = {}
                    try {
                      out.formatters = await window.sparkle.plugin.listFormatters()
                    } catch (e) {
                      out.formattersError = String((e && e.message) || e)
                    }
                    const btn = [...document.querySelectorAll('.editor-toolbar button')]
                      .find((b) => (b.textContent || '').trim() === '格式化')
                    out.hasButton = !!btn
                    out.buttonDisabled = btn ? btn.disabled : null
                    const read = () =>
                      (document.querySelector('.monaco-editor .view-lines')?.textContent ?? '')
                    out.before = read().slice(0, 200)

                    // 先直接走一次 IPC，把失败原因抓出来（点按钮看不出原因）
                    try {
                      const model = read()
                      const raw = await window.sparkle.plugin.formatDocument('cpp', model)
                      out.ipcReturned = raw === null ? null : String(raw).slice(0, 120)
                    } catch (e) {
                      out.ipcError = String((e && e.message) || e)
                    }

                    if (btn) btn.click()
                    await new Promise((r) => setTimeout(r, 3000))
                    out.after = read().slice(0, 200)
                    out.changed = out.before !== out.after
                    // 面板上的提示（成功/失败都会写在这里）
                    out.panelNote = (
                      document.querySelector('.debug-panel .output')?.textContent ?? ''
                    ).replace(/\\s+/g, ' ').trim().slice(0, 300)
                    return out
                  })()
                `);
					mainWindow.focus();
					mainWindow.webContents.focus();
					await new Promise((resolve) => setTimeout(resolve, 200));
					mainWindow.webContents.sendInputEvent({
						type: "keyDown",
						keyCode: "z",
						modifiers: ["control"]
					});
					mainWindow.webContents.sendInputEvent({
						type: "keyUp",
						keyCode: "z",
						modifiers: ["control"]
					});
					await new Promise((resolve) => setTimeout(resolve, 700));
					const afterUndo = await mainWindow.webContents.executeJavaScript(`(() => (document.querySelector('.monaco-editor .view-lines')?.textContent ?? '')).call(null).slice(0, 200)`);
					recordDiagnostic("formatProbe", {
						...beforeFormat,
						afterUndo,
						undoRestored: afterUndo === beforeFormat.before
					});
				} catch (error) {
					recordDiagnostic("formatProbe", { error: error instanceof Error ? error.message : String(error) });
				}
				if (process.env.SPARKLE_BENCH_UI === "1") try {
					recordDiagnostic("uiProbe", await mainWindow.webContents.executeJavaScript(`
                  (async () => {
                    const out = {}
                    const $ = (sel) => document.querySelector(sel)

                    // ── 1. 设置：读默认值 ──
                    try {
                      out.settings = await window.sparkle.settings.get()
                    } catch (e) { out.settingsError = String((e && e.message) || e) }

                    // ── 2. 设置面板能打开、主题能切 ──
                    const beforeBg = getComputedStyle(document.documentElement).getPropertyValue('--bg').trim()
                    out.bgBefore = beforeBg
                    document.querySelector('[data-view="settings"]')?.click()
                    await new Promise((r) => setTimeout(r, 600))
                    out.settingsPanelVisible = !!$('.settings-panel')
                    out.themeCards = document.querySelectorAll('.theme-card').length

                    // 点第二个主题（纯黑）
                    const cards = document.querySelectorAll('.theme-card')
                    if (cards.length > 1) {
                      cards[1].click()
                      await new Promise((r) => setTimeout(r, 600))
                    }
                    out.bgAfterTheme = getComputedStyle(document.documentElement).getPropertyValue('--bg').trim()
                    out.themeChanged = out.bgBefore !== out.bgAfterTheme

                    // ── 3. 字号能改 ──
                    const sliders = document.querySelectorAll('.settings-panel input[type="range"]')
                    out.sliderCount = sliders.length
                    if (sliders.length > 0) {
                      sliders[0].value = '20'
                      sliders[0].dispatchEvent(new Event('input', { bubbles: true }))
                      await new Promise((r) => setTimeout(r, 600))
                      out.editorFontSizeSaved = (await window.sparkle.settings.get()).editorFontSize
                    }

                    // ── 4. 停用插件 → 侧边栏图标消失 ──
                    // 必须走**界面上的复选框**，而不是直接调 IPC ——
                    // 直接调 IPC 会绕过渲染层的设置 store，
                    // 那样测出来的是"数据变了但界面没变"，和真实路径不同。
                    const hadOiIcon = !!document.querySelector('[data-view="oi"]')
                    out.oiIconBefore = hadOiIcon

                    const rows = [...document.querySelectorAll('.plugin-row')]
                    const oiRow = rows.find((r) => (r.textContent || '').includes('OI-Helper'))
                    out.oiRowFound = !!oiRow
                    const oiCheckbox = oiRow?.querySelector('input[type="checkbox"]')
                    if (oiCheckbox) {
                      oiCheckbox.checked = false
                      oiCheckbox.dispatchEvent(new Event('change', { bubbles: true }))
                      await new Promise((r) => setTimeout(r, 1200))
                    }
                    out.oiIconAfterDisable = !!document.querySelector('[data-view="oi"]')
                    out.oiHidden = hadOiIcon && !out.oiIconAfterDisable

                    // 再启用回来，确认能恢复
                    if (oiCheckbox) {
                      oiCheckbox.checked = true
                      oiCheckbox.dispatchEvent(new Event('change', { bubbles: true }))
                      await new Promise((r) => setTimeout(r, 1200))
                    }
                    out.oiIconRestored = !!document.querySelector('[data-view="oi"]')

                    // ── 5. 命令面板 ──
                    document.dispatchEvent(
                      new KeyboardEvent('keydown', {
                        key: 'P', ctrlKey: true, shiftKey: true, bubbles: true
                      })
                    )
                    window.dispatchEvent(
                      new KeyboardEvent('keydown', {
                        key: 'p', ctrlKey: true, shiftKey: true, bubbles: true
                      })
                    )
                    await new Promise((r) => setTimeout(r, 500))
                    const palette = $('.palette')
                    out.paletteOpened = !!palette
                    out.paletteItems = document.querySelectorAll('.palette-item').length
                    if (palette) {
                      const input = $('.palette-input')
                      if (input) {
                        input.value = '格式'
                        input.dispatchEvent(new Event('input', { bubbles: true }))
                        await new Promise((r) => setTimeout(r, 400))
                        out.afterFilterItems = document.querySelectorAll('.palette-item').length
                        out.firstMatch = ($('.palette-item .item-title') || {}).textContent || ''
                      }
                    }
                    return out
                  })()
                `));
				} catch (error) {
					recordDiagnostic("uiProbe", { error: error instanceof Error ? error.message : String(error) });
				}
				if (process.env.SPARKLE_BENCH_SPLIT === "1") try {
					recordDiagnostic("splitProbe", await mainWindow.webContents.executeJavaScript(`
                  (async () => {
                    window.__sparkleKeepSplit = ${process.env.SPARKLE_BENCH_KEEP_SPLIT === "1" ? "true" : "false"}
                    const out = {}
                    const panes = () => document.querySelectorAll('.pane')
                    const paneTitle = (i) => {
                      const t = document.querySelectorAll('.pane-title')[i]
                      return t ? t.textContent.trim() : ''
                    }
                    out.panesBefore = panes().length
                    out.keepSplitFlag = window.__sparkleKeepSplit === true

                    const btn = [...document.querySelectorAll('.editor-toolbar button')]
                      .find((b) => (b.textContent || '').trim() === '分屏')
                    out.hasSplitButton = !!btn
                    if (btn) btn.click()
                    await new Promise((r) => setTimeout(r, 900))
                    out.panesAfterSplit = panes().length
                    out.focusedCount = document.querySelectorAll('.pane.focused').length
                    out.secondPaneHasWelcome = !!panes()[1]?.querySelector('.pane-welcome')

                    // 在焦点窗格（第二个）里打开另一个文件：
                    // 点文件树的行，走的是真实用户路径（FileTree → openFile → 观察者 → 焦点窗格）
                    const otherFile = document.querySelector('[data-tree-path="b.py"]')
                    out.foundSecondFile = !!otherFile
                    if (otherFile) otherFile.click()
                    await new Promise((r) => setTimeout(r, 1200))

                    out.pane0Title = paneTitle(0)
                    out.pane1Title = paneTitle(1)
                    out.differentFiles =
                      out.pane0Title !== '' &&
                      out.pane1Title !== '' &&
                      out.pane0Title !== out.pane1Title
                    out.monacoInstances = document.querySelectorAll('.pane .monaco-editor').length

                    const orientBtn = [...document.querySelectorAll('.editor-toolbar button')]
                      .find((b) => ['⇅', '⇄'].includes((b.textContent || '').trim()))
                    if (orientBtn) {
                      orientBtn.click()
                      await new Promise((r) => setTimeout(r, 600))
                      out.orientationClass = document.querySelector('.panes')?.className || ''
                    }

                    const closeBtn = [...document.querySelectorAll('.editor-toolbar button')]
                      .find((b) => (b.textContent || '').trim() === '关窗格')
                    // 截图时用 SPARKLE_BENCH_KEEP_SPLIT=1 保留分屏状态
                    if (closeBtn && !(window.__sparkleKeepSplit === true)) {
                      closeBtn.click()
                      await new Promise((r) => setTimeout(r, 700))
                    }
                    out.panesAfterClose = panes().length
                    return out
                  })()
                `));
				} catch (error) {
					recordDiagnostic("splitProbe", { error: error instanceof Error ? error.message : String(error) });
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
