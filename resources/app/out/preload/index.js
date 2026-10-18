let electron = require("electron");
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
//#region src/shared/fs.ts
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
//#region src/shared/build.ts
var BUILD_CHANNELS = {
	scan: "build:scan",
	ensureCMakeLists: "build:ensureCMakeLists",
	compile: "build:compile",
	run: "build:run",
	revealBuildDir: "build:revealBuildDir"
};
//#endregion
//#region src/shared/search.ts
var SEARCH_CHANNELS = { query: "search:query" };
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
	debugEvent: "ide:debugEvent",
	appInfo: "ide:appInfo",
	openPath: "ide:openPath",
	setWorkspace: "ide:setWorkspace"
};
//#endregion
//#region src/shared/bench.ts
var BENCH_CHANNELS = {
	config: "bench:config",
	mark: "bench:mark",
	rendererReady: "bench:renderer-ready"
};
//#endregion
//#region src/shared/plugin.ts
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
//#region src/shared/luogu.ts
var LUOGU_CHANNELS = {
	search: "luogu:search",
	problem: "luogu:problem",
	openExternal: "luogu:openExternal"
};
//#endregion
//#region src/shared/settings.ts
var SETTINGS_CHANNELS = {
	get: "settings:get",
	set: "settings:set"
};
//#endregion
//#region src/preload/index.ts
/** 订阅主进程推送，返回取消订阅函数（组件卸载时必须调用，否则会泄漏监听器） */
function subscribe(channel, handler) {
	const listener = (_event, payload) => handler(payload);
	electron.ipcRenderer.on(channel, listener);
	return () => {
		electron.ipcRenderer.removeListener(channel, listener);
	};
}
/**
* 渲染层唯一的对外通道。
*
* sandbox: true 下 preload 只能使用 electron 暴露的少量模块，
* 这正是我们要的：渲染层拿不到 Node，能力必须由主进程显式授予。
* 代码执行也不例外 —— 渲染层只能"请求"，真正 spawn 由主进程做。
*/
electron.contextBridge.exposeInMainWorld("sparkle", {
	/** 冷启动基准用：通知主进程"首屏已真实渲染完成" */
	benchRendererReady: (info) => {
		electron.ipcRenderer.send(BENCH_CHANNELS.rendererReady, info);
	},
	/** 基准测试专用：读配置、上报渲染层耗时 */
	bench: {
		config: () => electron.ipcRenderer.invoke(BENCH_CHANNELS.config),
		mark: (mark) => {
			electron.ipcRenderer.send(BENCH_CHANNELS.mark, mark);
		}
	},
	run: {
		interpreter: () => electron.ipcRenderer.invoke(RUN_CHANNELS.interpreter),
		start: (request) => electron.ipcRenderer.invoke(RUN_CHANNELS.start, request),
		stop: (runId) => electron.ipcRenderer.invoke(RUN_CHANNELS.stop, runId),
		onStdout: (handler) => subscribe(RUN_CHANNELS.stdout, handler),
		onStderr: (handler) => subscribe(RUN_CHANNELS.stderr, handler),
		onFinished: (handler) => subscribe(RUN_CHANNELS.finished, handler)
	},
	fs: {
		openFolder: () => electron.ipcRenderer.invoke(FS_CHANNELS.openFolder),
		currentWorkspace: () => electron.ipcRenderer.invoke(FS_CHANNELS.currentWorkspace),
		readDirectory: (path) => electron.ipcRenderer.invoke(FS_CHANNELS.readDirectory, path),
		readFile: (path) => electron.ipcRenderer.invoke(FS_CHANNELS.readFile, path),
		saveFile: (path, content) => electron.ipcRenderer.invoke(FS_CHANNELS.saveFile, path, content),
		createFile: (parent, name) => electron.ipcRenderer.invoke(FS_CHANNELS.createFile, parent, name),
		createDirectory: (parent, name) => electron.ipcRenderer.invoke(FS_CHANNELS.createDirectory, parent, name),
		renameEntry: (path, newName) => electron.ipcRenderer.invoke(FS_CHANNELS.renameEntry, path, newName),
		deleteEntry: (path, recursive) => electron.ipcRenderer.invoke(FS_CHANNELS.deleteEntry, path, recursive)
	},
	build: {
		scan: () => electron.ipcRenderer.invoke(BUILD_CHANNELS.scan),
		ensureCMakeLists: (project) => electron.ipcRenderer.invoke(BUILD_CHANNELS.ensureCMakeLists, project),
		compile: (request) => electron.ipcRenderer.invoke(BUILD_CHANNELS.compile, request),
		run: (request, executable) => electron.ipcRenderer.invoke(BUILD_CHANNELS.run, request, executable)
	},
	search: { query: (options) => electron.ipcRenderer.invoke(SEARCH_CHANNELS.query, options) },
	ide: {
		compileFile: (request) => electron.ipcRenderer.invoke(IDE_CHANNELS.compileFile, request),
		runFile: (request) => electron.ipcRenderer.invoke(IDE_CHANNELS.runFile, request),
		runInConsole: (request) => electron.ipcRenderer.invoke(IDE_CHANNELS.runInConsole, request),
		openFileDialog: () => electron.ipcRenderer.invoke(IDE_CHANNELS.openFileDialog),
		debugStart: (request) => electron.ipcRenderer.invoke(IDE_CHANNELS.debugStart, request),
		debugCommand: (action) => electron.ipcRenderer.invoke(IDE_CHANNELS.debugCommand, action),
		debugStop: () => electron.ipcRenderer.invoke(IDE_CHANNELS.debugStop),
		onDebugEvent: (handler) => subscribe(IDE_CHANNELS.debugEvent, handler),
		appInfo: () => electron.ipcRenderer.invoke(IDE_CHANNELS.appInfo),
		openPath: (path) => electron.ipcRenderer.invoke(IDE_CHANNELS.openPath, path),
		setWorkspace: (directory) => electron.ipcRenderer.invoke(IDE_CHANNELS.setWorkspace, directory)
	},
	plugin: {
		list: () => electron.ipcRenderer.invoke(PLUGIN_CHANNELS.list),
		openFolder: () => electron.ipcRenderer.invoke(PLUGIN_CHANNELS.openFolder),
		setGranted: (id, permissions) => electron.ipcRenderer.invoke(PLUGIN_CHANNELS.setGranted, id, permissions),
		activate: (id) => electron.ipcRenderer.invoke(PLUGIN_CHANNELS.activate, id),
		deactivate: (id) => electron.ipcRenderer.invoke(PLUGIN_CHANNELS.deactivate, id),
		provideCompletions: (payload) => electron.ipcRenderer.invoke(PLUGIN_CHANNELS.provideCompletions, payload),
		cancel: (requestId) => electron.ipcRenderer.invoke(PLUGIN_CHANNELS.cancel, requestId),
		onChanged: (handler) => subscribe(PLUGIN_CHANNELS.changed, handler),
		/** 求解器：算法插件（OI-Helper）用 */
		listSolvers: () => electron.ipcRenderer.invoke(PLUGIN_CHANNELS.listSolvers),
		runSolver: (pluginId, solverId, inputs) => electron.ipcRenderer.invoke(PLUGIN_CHANNELS.runSolver, {
			pluginId,
			solverId,
			inputs
		})
	},
	toolchain: {
		detect: (force) => electron.ipcRenderer.invoke(TOOLCHAIN_CHANNELS.detect, force),
		install: (toolId) => electron.ipcRenderer.invoke(TOOLCHAIN_CHANNELS.install, toolId),
		cancel: () => electron.ipcRenderer.invoke(TOOLCHAIN_CHANNELS.cancel),
		remove: (toolId) => electron.ipcRenderer.invoke(TOOLCHAIN_CHANNELS.remove, toolId),
		openFolder: () => electron.ipcRenderer.invoke(TOOLCHAIN_CHANNELS.openFolder),
		browse: (toolId) => electron.ipcRenderer.invoke(TOOLCHAIN_CHANNELS.browse, toolId),
		setManualPath: (toolId, path) => electron.ipcRenderer.invoke(TOOLCHAIN_CHANNELS.setManualPath, toolId, path),
		selectCandidate: (executable) => electron.ipcRenderer.invoke(TOOLCHAIN_CHANNELS.selectCandidate, executable),
		reset: () => electron.ipcRenderer.invoke("toolchain:reset"),
		onProgress: (handler) => subscribe(TOOLCHAIN_CHANNELS.progress, handler)
	},
	luogu: {
		search: (options) => electron.ipcRenderer.invoke(LUOGU_CHANNELS.search, options),
		problem: (pid) => electron.ipcRenderer.invoke(LUOGU_CHANNELS.problem, pid),
		openExternal: (url) => electron.ipcRenderer.invoke(LUOGU_CHANNELS.openExternal, url)
	},
	settings: {
		get: () => electron.ipcRenderer.invoke(SETTINGS_CHANNELS.get),
		set: (update) => electron.ipcRenderer.invoke(SETTINGS_CHANNELS.set, update)
	}
});
//#endregion
