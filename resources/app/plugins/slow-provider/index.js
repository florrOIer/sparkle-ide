/**
 * 用来验证"取消"是真的生效，而不是写在文档里的空话。
 *
 * 它的补全处理器会分片等待约 2 秒。如果宿主期间取消了这次请求，
 * 取消令牌会在下一片被观察到，插件立刻停止计算并**打一条日志**。
 * 基准测试就是靠这条日志判断取消链路是否打通：
 *
 *   编辑器取消 → 主进程 → 沙箱 → 插件的 token
 *
 * 任何一环断了，这条日志都不会出现。
 */

const TOTAL_SLICES = 40
const SLICE_MS = 50

export async function activate(api) {
  api.log('慢速补全插件已激活')

  api.registerCompletionProvider('javascript', async (context, token) => {
    // 注册取消回调，验证"事件式"取消也能收到
    let notified = false
    token.onCancellationRequested(() => {
      notified = true
    })

    for (let slice = 0; slice < TOTAL_SLICES; slice += 1) {
      if (token.isCancellationRequested()) {
        api.log(`CANCELLED_DETECTED 在第 ${slice} 片（事件回调收到=${notified}）`)
        return { items: [] }
      }
      await new Promise((resolve) => setTimeout(resolve, SLICE_MS))
    }

    api.log('慢速补全算完了（本次没有被取消）')
    return {
      items: [
        {
          label: '慢速补全结果',
          detail: '耗时约 2 秒',
          kind: 'text',
          insertText: 'slow_result'
        }
      ]
    }
  })
}
