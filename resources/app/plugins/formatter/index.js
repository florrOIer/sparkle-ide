/**
 * 格式化插件：C++ / C / Python 的自动格式化。
 *
 * 这是「编辑器访问」能力的第一个真实用例，也顺便回答一个现实问题：
 * 这台机器上没有 clang-format / astyle / uncrustify，而 github 打不开、
 * clang-format 下不下来。所以格式化逻辑自己写。
 *
 * 三条设计原则（都是被失败教训定下来的）：
 *
 * 1. **绝不破坏字符串**。
 *    我第一版用"找最后一个非空格字符"来删行尾空格，
 *    结果 `"yes   "` 被截成 `"` —— 因为字符串内部的字符不算"非空格"。
 *    现在改成"字符串内的每一个字符都保留"，注释按普通文本处理。
 *
 * 2. **不算缩进层级之外的结构**。
 *    Python 只把 tab 换成空格、删行尾空格 —— **不改缩进层级**。
 *    Python 靠缩进表达语义，猜错一层就是改变程序行为，
 *    一个格式化工具把代码意思改掉，比不格式化糟得多。
 *
 * 3. **幂等**。格式化两次结果必须完全一样（verify 脚本会验）。
 *
 * 不需要任何权限：它只接收宿主送来的文本、返回新文本，
 * 既不读文件也不直接改编辑器（真正写入由宿主用可撤销编辑完成）。
 */

/* ──────────────── 通用：安全地删掉行尾空白 ──────────────── */

/**
 * 删掉行尾空白，但**完整保留字符串字面量**。
 *
 * 关键点：字符串内部的空格是有意义的（`"abc   "` 不能变成 `"abc"`），
 * 所以字符串里的**每一个字符**都要被算作"要保留的内容"。
 *
 * 注释按普通文本处理（注释末尾的空格删掉无害）。
 *
 * 已知的小妥协：注释里出现 `'` 或 `"` 时会被误判成字符串开头，
 * 于是那行的行尾空格不会被删。这是**安全方向的妥协** ——
 * 少删几个空格，远好过多删坏一个字符串。
 */
function stripTrailingSpaceSafely(line) {
  let inString = false
  let quote = ''
  let lastKeep = -1

  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i]
    const prev = i > 0 ? line[i - 1] : ''

    if (inString) {
      // 字符串里的任何字符都保留（包括空格）
      lastKeep = i
      if (prev !== '\\' && ch === quote) inString = false
      continue
    }

    if (ch === '"' || ch === "'") {
      inString = true
      quote = ch
      lastKeep = i
      continue
    }

    if (ch !== ' ' && ch !== '\t') lastKeep = i
  }

  if (lastKeep < 0) return ''
  return line.slice(0, lastKeep + 1)
}

/** 这一行净增加了多少层大括号（跳过字符串与行注释） */
function netBraces(line) {
  let net = 0
  let inString = false
  let quote = ''

  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i]
    const prev = i > 0 ? line[i - 1] : ''

    if (inString) {
      if (prev !== '\\' && ch === quote) inString = false
      continue
    }
    if (ch === '"' || ch === "'") {
      inString = true
      quote = ch
      continue
    }
    // 行注释：后面全是注释，括号不算
    if (ch === '/' && line[i + 1] === '/') break

    if (ch === '{') net += 1
    else if (ch === '}') net -= 1
  }

  return net
}

/* ─────────────────────────── C++ ─────────────────────────── */

/**
 * 只补空格的保守处理（全程跳过字符串与行注释）：
 *   `if(` → `if (`、`main(){` → `main() {`、`}else{` → `} else {`、`,` 后补空格
 *
 * **刻意不做**大括号换行风格统一（Allman vs K&R 都有人用，
 * 强行统一会让用户代码风格大改，而他可能只是想让缩进整齐）。
 */
function fixSpacing(line) {
  let result = ''
  let inString = false
  let quote = ''
  let inLineComment = false

  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i]
    const prev = i > 0 ? line[i - 1] : ''

    if (inLineComment) {
      result += ch
      continue
    }

    if (inString) {
      result += ch
      if (prev !== '\\' && ch === quote) inString = false
      continue
    }

    if (ch === '"' || ch === "'") {
      inString = true
      quote = ch
      result += ch
      continue
    }

    if (ch === '/' && line[i + 1] === '/') {
      inLineComment = true
      result += ch
      continue
    }

    // `if(` `for(` 这类关键字后补空格；函数调用 foo( 不能动
    if (ch === '(') {
      if (/(?:^|[^\w.])(?:if|for|while|switch|catch|return)$/.test(result)) result += ' '
      result += ch
      continue
    }

    // 左大括号前补空格：`main(){` → `main() {`
    if (ch === '{') {
      const last = result[result.length - 1]
      if (last && !' \t({[;'.includes(last)) result += ' '
      result += ch
      continue
    }

    // 右大括号后若是关键字，补空格：`}else` → `} else`
    if (ch === '}') {
      result += ch
      const next = line[i + 1]
      if (next && /[A-Za-z_]/.test(next)) result += ' '
      continue
    }

    // 逗号后补一个空格（后面紧跟非空白、非右括号时）
    if (ch === ',') {
      result += ch
      const next = line[i + 1]
      if (next && next !== ' ' && next !== '\t' && next !== ')' && next !== '}') result += ' '
      continue
    }

    result += ch
  }

  return result
}

/**
 * C++ / C 格式化：按大括号层级重算缩进（4 空格）+ 安全删行尾空格 + 补关键字空格。
 *
 * 缩进算法只有两条规则，简单可验证：
 *   · 行首是 `}` → 这一行的缩进用「当前层 - 1」
 *   · 整行的净大括号变化量累加到当前层
 * 这样 `} else {`（净变化 0）自然落在正确的层上。
 */
function formatBraceLanguage(source) {
  const lines = source.split('\n')
  const out = []
  let depth = 0

  for (const rawLine of lines) {
    const trimmed = stripTrailingSpaceSafely(rawLine.trim())

    if (trimmed === '') {
      out.push('')
      continue
    }

    // 行首的 } 属于外层
    let lineDepth = depth
    if (trimmed.startsWith('}')) lineDepth = Math.max(0, depth - 1)

    out.push('    '.repeat(lineDepth) + fixSpacing(trimmed))
    depth = Math.max(0, depth + netBraces(trimmed))
  }

  // 文件末尾保留恰好一个换行
  while (out.length > 0 && out[out.length - 1] === '') out.pop()
  return out.join('\n') + '\n'
}

/* ─────────────────────────── Python ─────────────────────────── */

/**
 * Python 只做两件安全的事：
 *   1. 行首缩进里的 tab → 4 空格（混用 tab 和空格会直接报 IndentationError，
 *      这是初学者最常见的问题之一）
 *   2. 删行尾空格（字符串内的不动）
 *
 * **不动缩进层级** —— 见文件顶部第 2 条原则。
 */
function formatPython(source) {
  const lines = source.split('\n')
  const out = lines.map((line) => {
    const match = /^([ \t]*)/.exec(line)
    const leading = match ? match[1] : ''
    const rest = line.slice(leading.length)
    const fixedIndent = leading.replace(/\t/g, '    ')
    return fixedIndent + stripTrailingSpaceSafely(rest)
  })

  while (out.length > 0 && out[out.length - 1] === '') out.pop()
  return out.join('\n') + '\n'
}

/* ─────────────────────────── 注册 ─────────────────────────── */

export async function activate(api) {
  /*
   * 注意：这里**绝对不能**写 `api.registerFormatter = ...`。
   * api 是 contextBridge 暴露到插件世界的只读对象，赋值会抛 TypeError，
   * 而异常发生在 activate 里会被宿主报成"激活超时（4000 ms）"，
   * 真正的原因完全看不到 —— OI-Helper 就是这么挂过一次的。
   */

  api.registerFormatter('cpp', (content) => formatBraceLanguage(content))
  api.registerFormatter('c', (content) => formatBraceLanguage(content))
  api.registerFormatter('python', (content) => formatPython(content))

  api.log('格式化插件已激活：C / C++ / Python')
}
