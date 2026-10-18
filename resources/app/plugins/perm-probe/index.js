/**
 * 权限探针。
 *
 * 它**没有申请任何权限**，但激活后立刻尝试读工作区文件。
 * 期望结果是主进程拒绝，并在日志里看到 PERMISSION_PROBE_DENIED。
 *
 * 如果哪天看到 PERMISSION_PROBE_UNEXPECTED，说明权限模型被绕过了 ——
 * 那是必须立刻处理的安全回归。
 */

export async function activate(api) {
  api.log('权限探针已激活（未申请任何权限）')

  try {
    const file = await api.workspace.readFile('main.py')
    api.log(`PERMISSION_PROBE_UNEXPECTED 未授权却读到了文件，长度=${String(file && file.content).length}`)
  } catch (error) {
    api.log(`PERMISSION_PROBE_DENIED ${String((error && error.message) || error)}`)
  }
}
