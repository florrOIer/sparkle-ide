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
	network: { fetch: (url, options) => electron.ipcRenderer.invoke(CHANNELS.sandboxRequest, {
		method: "network.fetch",
		params: {
			url,
			method: options?.method ?? "GET"
		}
	}) }
});
//#endregion
