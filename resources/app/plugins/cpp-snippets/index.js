/**
 * 示例插件：C++ 竞赛片段（插件开发教程第 6 节）。
 *
 * 这个插件刻意**零权限** —— 提供补全不需要读文件、不需要联网。
 * 你可以直接改 SNIPPETS 数组，重启 IDE 就能看到变化。
 */

const SNIPPETS = [
  {
    label: '快速读入',
    detail: '关闭同步 + 解绑 cin/cout',
    kind: 'snippet',
    insertText: 'ios::sync_with_stdio(false);\ncin.tie(nullptr);'
  },
  {
    label: 'freopen 文件输入',
    detail: '从 in.txt 读、写到 out.txt',
    kind: 'snippet',
    insertText: 'freopen("in.txt", "r", stdin);\nfreopen("out.txt", "w", stdout);'
  },
  {
    label: 'for 循环',
    detail: '从 1 开始的标准写法',
    kind: 'snippet',
    insertText: 'for (int i = 1; i <= n; i++) {\n    \n}'
  },
  {
    label: '二分查找',
    detail: '找第一个满足条件的下标',
    kind: 'snippet',
    insertText:
      'int lo = 1, hi = n, ans = -1;\nwhile (lo <= hi) {\n    int mid = lo + (hi - lo) / 2;\n    if (check(mid)) { ans = mid; hi = mid - 1; }\n    else lo = mid + 1;\n}'
  },
  {
    label: '读入数组',
    detail: '读 n 个数到 vector',
    kind: 'snippet',
    insertText: 'vector<int> a(n);\nfor (int i = 0; i < n; i++) cin >> a[i];'
  }
]

/** 取光标前正在输入的词（支持中文变量名） */
function currentWord(linePrefix) {
  const match = /([\p{L}\p{N}_]*)$/u.exec(linePrefix)
  return match ? match[1] : ''
}

export async function activate(api) {
  api.log(`C++ 竞赛片段已激活，共 ${SNIPPETS.length} 条`)

  api.registerCompletionProvider('cpp', async (context, token) => {
    if (token.isCancellationRequested()) return { items: [] }

    const word = currentWord(context.linePrefix).toLowerCase()
    const items = SNIPPETS.filter((item) =>
      word === '' ? true : item.label.toLowerCase().startsWith(word)
    )

    return { items }
  })
}
