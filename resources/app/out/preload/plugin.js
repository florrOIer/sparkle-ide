let electron = require("electron");
//#endregion
//#region src/preload/plugin.ts
/**
* 插件沙箱的 preload —— 插件能接触到的**全部** API。
*
* 这里没有任何 Node 能力：没有 fs、没有 child_process、没有 require。
* 插件想要文件或网络，只能调下面的 workspace.* / network.*，
* 而它们最终由主进程按权限决定给不给。
*
* 注意通道名来自 ./pluginChannels，**不是** ../shared/plugin ——
* 原因见 pluginChannels.ts：沙箱 preload 不能 require 打包器抽出的公共 chunk，
* 所以两个 preload 入口之间不能共享任何运行时模块。
*/
var CHANNELS = {
	sandboxActivate: "plugin-sandbox:activate",
	sandboxRpc: "plugin-sandbox:rpc",
	sandboxCancel: "plugin-sandbox:cancel",
	sandboxReady: "plugin-sandbox:ready",
	sandboxReply: "plugin-sandbox:reply",
	sandboxRegistered: "plugin-sandbox:registered",
	sandboxRequest: "plugin-sandbox:request",
	sandboxFatal: "plugin-sandbox:fatal",
	sandboxLog: "plugin-sandbox:log"
};
var completionHandlers = /* @__PURE__ */ new Map();
var activeTokens = /* @__PURE__ */ new Map();
/** 求解器：OI-Helper 这类"算法插件"用。注册信息发给主进程，run 函数留在沙箱里。 */
var solverHandlers = /* @__PURE__ */ new Map();
var formatterHandlers = /* @__PURE__ */ new Map();
var commandHandlers = /* @__PURE__ */ new Map();
function describeCommandResult(value) {
	if (typeof value === "string") return value.slice(0, 300);
	if (value === void 0 || value === null) return "";
	try {
		return JSON.stringify(value).slice(0, 300);
	} catch {
		return "";
	}
}
function createToken(requestId) {
	let cancelled = false;
	const listeners = [];
	activeTokens.set(requestId, { cancel: () => {
		cancelled = true;
		for (const listener of listeners.splice(0)) try {
			listener();
		} catch {}
	} });
	return {
		isCancellationRequested: () => cancelled,
		onCancellationRequested: (listener) => {
			if (typeof listener !== "function") return;
			if (cancelled) {
				try {
					listener();
				} catch {}
				return;
			}
			listeners.push(listener);
		}
	};
}
function reply(requestId, ok, result, error) {
	electron.ipcRenderer.send(CHANNELS.sandboxReply, {
		requestId,
		ok,
		result,
		error
	});
}
electron.ipcRenderer.on(CHANNELS.sandboxRpc, async (_event, payload) => {
	const message = payload;
	const requestId = String(message?.requestId ?? "");
	if (!requestId) return;
	if (message?.method === "runSolver") {
		const params = message.params ?? {};
		const solver = solverHandlers.get(String(params.solverId ?? ""));
		if (!solver) {
			reply(requestId, false, void 0, "该插件没有注册这个求解器");
			return;
		}
		try {
			reply(requestId, true, await solver.run(params.inputs ?? {}));
		} catch (error) {
			reply(requestId, false, void 0, String(error?.message ?? error));
		}
		return;
	}
	if (message?.method === "runCommand") {
		const params = message.params ?? {};
		const handler = commandHandlers.get(String(params.commandId ?? ""));
		if (!handler) {
			reply(requestId, false, void 0, "该插件没有注册这个命令");
			return;
		}
		try {
			reply(requestId, true, describeCommandResult(await handler()));
		} catch (error) {
			reply(requestId, false, void 0, String(error?.message ?? error));
		}
		return;
	}
	if (message?.method === "formatDocument") {
		const params = message.params ?? {};
		const handler = formatterHandlers.get(String(params.languageId ?? ""));
		if (!handler) {
			reply(requestId, false, void 0, "该插件没有为这个语言注册格式化器");
			return;
		}
		try {
			const formatted = await handler(String(params.content ?? ""), String(params.languageId ?? ""));
			if (typeof formatted !== "string") {
				reply(requestId, false, void 0, "格式化器必须返回字符串");
				return;
			}
			reply(requestId, true, formatted);
		} catch (error) {
			reply(requestId, false, void 0, String(error?.message ?? error));
		}
		return;
	}
	if (message?.method !== "provideCompletions") {
		reply(requestId, false, void 0, `不支持的方法：${String(message?.method)}`);
		return;
	}
	const params = message.params ?? {};
	const handler = completionHandlers.get(String(params.languageId ?? ""));
	if (!handler) {
		reply(requestId, false, void 0, "该插件没有为该语言注册补全提供者");
		return;
	}
	const token = createToken(requestId);
	try {
		reply(requestId, true, await handler(params.context, token));
	} catch (error) {
		reply(requestId, false, void 0, String(error?.message ?? error));
	} finally {
		activeTokens.delete(requestId);
	}
});
electron.ipcRenderer.on(CHANNELS.sandboxCancel, (_event, payload) => {
	const requestId = String(payload?.requestId ?? "");
	activeTokens.get(requestId)?.cancel();
});
electron.contextBridge.exposeInMainWorld("sparklePlugin", {
	/** 引导脚本在入口加载并 activate 完成后调用 */
	notifyReady: () => {
		electron.ipcRenderer.send(CHANNELS.sandboxReady);
	},
	/** 顶层异常上报。不上报的话用户只会看到"插件没反应"，无从排查。 */
	reportFatal: (message) => {
		electron.ipcRenderer.send(CHANNELS.sandboxFatal, String(message).slice(0, 2e3));
	},
	log: (message) => {
		electron.ipcRenderer.send(CHANNELS.sandboxLog, String(message).slice(0, 1e3));
	},
	registerCompletionProvider: (languageId, handler) => {
		if (typeof languageId !== "string" || !languageId) return;
		if (typeof handler !== "function") return;
		completionHandlers.set(languageId, handler);
		electron.ipcRenderer.send(CHANNELS.sandboxRegistered, {
			kind: "completions",
			value: languageId
		});
	},
	/**
	* 注册一个"求解器"。
	*
	* 插件只提供算法与结构化的可视化描述，**不返回 HTML**：
	* 渲染由宿主用可信代码完成。所以插件即使被投毒，也只能画出一张图，
	* 碰不到宿主的 DOM 或别的面板。
	*/
	registerSolver: (registration) => {
		if (!registration || typeof registration.id !== "string") return;
		if (typeof registration.run !== "function") return;
		solverHandlers.set(registration.id, registration);
		electron.ipcRenderer.send(CHANNELS.sandboxRegistered, {
			kind: "solver",
			value: JSON.stringify({
				id: registration.id,
				title: registration.title,
				description: registration.description,
				category: registration.category ?? "其它",
				inputs: registration.inputs ?? []
			})
		});
	},
	/**
	* 注册一个"格式化器"。
	*
	* 用户点工具栏的「格式化」（或 Shift+Alt+F）时会调用它：
	* 主进程把当前文件全文发进来，你把格式化后的全文返回。
	* 宿主会用一次**可撤销的编辑**把结果写进编辑器，所以用户能 Ctrl+Z 撤回。
	*
	* 需要 editor 权限。
	*/
	registerFormatter: (languageId, handler) => {
		if (typeof languageId !== "string" || !languageId) return;
		if (typeof handler !== "function") return;
		formatterHandlers.set(languageId, handler);
		electron.ipcRenderer.send(CHANNELS.sandboxRegistered, {
			kind: "formatter",
			value: languageId
		});
	},
	/**
	* 注册一个命令（会在命令面板 Ctrl+Shift+P 里出现，用户可搜索执行）。
	*
	* 命令 id 建议带插件前缀，例如 sparkle.formatter.sample，
	* 并同时写进 sparkle.json 的 contributes.commands —— 清单负责**显示名**，
	* 这里负责**实现**。只写清单不注册，面板里不会出现（因为点了会失败，不如不显示）。
	*/
	registerCommand: (id, handler) => {
		if (typeof id !== "string" || !id.trim()) return;
		if (typeof handler !== "function") return;
		commandHandlers.set(id.trim().slice(0, 120), handler);
		electron.ipcRenderer.send(CHANNELS.sandboxRegistered, {
			kind: "command",
			value: id.trim()
		});
	},
	/** 编辑器访问。需要 editor 权限，未授权时主进程会拒绝并给出可读原因。 */
	editor: {
		/** 读当前活动的文档（含版本号，改的时候要带回来） */
		getActiveDocument: () => electron.ipcRenderer.invoke(CHANNELS.sandboxRequest, {
			method: "editor.getActiveDocument",
			params: {}
		}),
		/**
		* 修改当前活动的文档。
		*
		* request 必须带上 getActiveDocument 拿到的 version ——
		* 版本不一致会被整批拒绝（宁可失败重试，也不要按错误的行号改坏代码）。
		* 修改可以用 Ctrl+Z 撤销。
		*/
		applyEdits: (request) => electron.ipcRenderer.invoke(CHANNELS.sandboxRequest, {
			method: "editor.applyEdits",
			params: request
		})
	},
	/** 受权限约束的能力。没有授权时主进程会拒绝，并给出可读的原因。 */
	workspace: {
		readFile: (path) => electron.ipcRenderer.invoke(CHANNELS.sandboxRequest, {
			method: "workspace.readFile",
			params: { path }
		}),
		writeFile: (path, content) => electron.ipcRenderer.invoke(CHANNELS.sandboxRequest, {
			method: "workspace.writeFile",
			params: {
				path,
				content
			}
		})
	},
	/**
	* 文件系统（同级权限）。需要 fs:read / fs:write。
	*
	* 和 workspace.* 的区别在路径：这里既接受绝对路径（C:\...、/home/...），
	* 也接受相对路径（按当前工作区解析）。没有"只能在项目里"的限制，
	* 也就是说读写范围等价于 IDE 自己。
	*
	* 唯一的禁区是写：插件目录、settings.json、plugin-grants.json。
	* 前者防止插件给自己写新版本，后两者防止插件绕过权限直接改设置。
	*/
	filesystem: {
		readFile: (path, options) => electron.ipcRenderer.invoke(CHANNELS.sandboxRequest, {
			method: "fs.readFile",
			params: {
				path,
				encoding: options?.encoding
			}
		}),
		writeFile: (path, content, options) => electron.ipcRenderer.invoke(CHANNELS.sandboxRequest, {
			method: "fs.writeFile",
			params: {
				path,
				content,
				encoding: options?.encoding
			}
		}),
		readdir: (path) => electron.ipcRenderer.invoke(CHANNELS.sandboxRequest, {
			method: "fs.readdir",
			params: { path }
		}),
		stat: (path) => electron.ipcRenderer.invoke(CHANNELS.sandboxRequest, {
			method: "fs.stat",
			params: { path }
		}),
		mkdir: (path) => electron.ipcRenderer.invoke(CHANNELS.sandboxRequest, {
			method: "fs.mkdir",
			params: { path }
		}),
		rename: (from, to) => electron.ipcRenderer.invoke(CHANNELS.sandboxRequest, {
			method: "fs.rename",
			params: {
				from,
				to
			}
		}),
		unlink: (path) => electron.ipcRenderer.invoke(CHANNELS.sandboxRequest, {
			method: "fs.unlink",
			params: { path }
		})
	},
	/**
	* IDE 设置。需要 config 权限。
	*
	* getAll 返回生效中的完整设置（已经过白名单清洗），
	* set 传一个 patch 对象，宿主会合并、校验、写盘，然后广播给界面。
	* disabledPlugins 永远不能通过这里修改 —— 否则插件能给自己提权。
	*/
	config: {
		getAll: () => electron.ipcRenderer.invoke(CHANNELS.sandboxRequest, {
			method: "config.get",
			params: {}
		}),
		set: (patch) => electron.ipcRenderer.invoke(CHANNELS.sandboxRequest, {
			method: "config.set",
			params: { patch }
		})
	},
	network: { fetch: (url, options) => electron.ipcRenderer.invoke(CHANNELS.sandboxRequest, {
		method: "network.fetch",
		params: {
			url,
			method: options?.method ?? "GET"
		}
	}) }
});
//#endregion
