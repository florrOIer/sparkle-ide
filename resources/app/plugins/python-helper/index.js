/**
 * 示例插件：Python 初学者助手。
 *
 * 它刻意**不申请任何权限** —— 这是权限模型的示范：
 * 提供补全不需要读文件、不需要联网，所以它拿到的是零权限沙箱。
 * 如果它哪天想读工作区文件，就必须在 sparkle.json 里声明 workspace:read，
 * 并在插件面板里得到用户授权，否则请求会被主进程直接拒绝。
 *
 * 这里用到的东西全部来自 window.sparklePlugin（沙箱 preload 注入）：
 * 没有 require、没有 process、没有 fs。
 */

const COMPLETIONS = [
  {
    label: 'print',
    detail: '输出到屏幕',
    kind: 'function',
    insertText: 'print()'
  },
  {
    label: 'input',
    detail: '读取用户输入',
    kind: 'function',
    insertText: 'input()'
  },
  {
    label: 'range',
    detail: '生成一串数字',
    kind: 'function',
    insertText: 'range()'
  },
  {
    label: 'len',
    detail: '取长度',
    kind: 'function',
    insertText: 'len()'
  },
  {
    label: 'for 循环',
    detail: '重复执行若干次',
    kind: 'snippet',
    insertText: 'for i in range(10):\n    pass'
  },
  {
    label: 'if 判断',
    detail: '条件判断',
    kind: 'snippet',
    insertText: 'if 条件:\n    pass'
  },
  {
    label: 'while 循环',
    detail: '条件满足时一直重复',
    kind: 'snippet',
    insertText: 'while 条件:\n    pass'
  },
  {
    label: 'def 函数',
    detail: '定义一个函数',
    kind: 'snippet',
    insertText: 'def 函数名(参数):\n    return 参数'
  },
  {
    label: '程序入口',
    detail: '只有当文件被直接运行时才执行',
    kind: 'snippet',
    insertText: 'if __name__ == "__main__":\n    pass'
  },
  {
    label: '转成整数',
    detail: '把输入的文字变成整数',
    kind: 'function',
    insertText: 'int()'
  }
]

/** 取出光标前正在输入的那个词 */
function currentWord(linePrefix) {
  const match = /([\p{L}\p{N}_]*)$/u.exec(linePrefix)
  return match ? match[1] : ''
}

export async function activate(api) {
  api.log('Python 初学者助手已激活（零权限）')

  api.registerCompletionProvider('python', async (context, token) => {
    // 宿主可能已经取消这次请求（例如用户又敲了一个字符）。
    // 先检查一次，能省掉后面全部计算。
    if (token.isCancellationRequested()) {
      return { items: [] }
    }

    const word = currentWord(context.linePrefix)

    const items = COMPLETIONS.filter((item) => {
      if (word === '') return true
      return item.label.toLowerCase().startsWith(word.toLowerCase())
    }).map((item) => ({
      label: item.label,
      detail: item.detail,
      kind: item.kind,
      insertText: item.insertText
    }))

    return { items }
  })
}
