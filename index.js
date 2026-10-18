/**
 * OI-Helper —— 算法与数据结构可视化插件。
 *
 * 设计上的三个要点：
 *
 * 1. **零权限**。这里全是纯计算，不需要读文件、不需要联网。
 *    一个算法插件要文件权限是没道理的，所以清单里 permissions 是空数组。
 *
 * 2. **只返回结构化的可视化描述，绝不返回 HTML**。
 *    宿主拿到的是 { kind: 'graph', nodes: [...], edges: [...] } 这样的数据，
 *    由宿主用可信代码画出来。所以这个插件即使被投毒，也只能"画一张图"，
 *    碰不到宿主的界面。附带好处是配色与交互统一。
 *
 * 3. **输入用最简单的一行行文本**，不做花哨的语法。
 *    OI 选手习惯直接粘贴测试数据，所以解析要宽容：
 *    多余空格、空行、行尾注释都不该报错。
 */

/* ─────────────────────── 输入解析 ─────────────────────── */

/** 把文本切成若干行有内容的行（去掉空行与 # 注释） */
function lines(text) {
  return String(text ?? '')
    .split(/\r?\n/)
    .map((line) => line.replace(/#.*$/, '').trim())
    .filter((line) => line.length > 0)
}

/** 解析一行整数数组："1 2 3" 或 "1,2,3" 都行 */
function numbers(text) {
  const matches = String(text ?? '').match(/-?\d+/g)
  return matches ? matches.map(Number) : []
}

/**
 * 解析图：第一行 "n m"，后面 m 行 "u v [w]"。
 * 返回 { n, edges }，并把点编号统一成从 0 开始（用户习惯从 1 开始）。
 */
function parseGraph(text, weighted) {
  const rows = lines(text)
  if (rows.length === 0) throw new Error('请输入图的数据：第一行是「点数 边数」，后面每行一条边')

  const head = numbers(rows[0])
  const n = head[0] ?? 0
  const m = head[1] ?? rows.length - 1
  if (n <= 0) throw new Error('点数必须大于 0')
  if (n > 200) throw new Error('点数建议不超过 200，否则图会画得很乱')

  const edges = []
  for (let index = 1; index < rows.length && edges.length < m; index += 1) {
    const parts = numbers(rows[index])
    if (parts.length < 2) continue
    edges.push({
      from: parts[0] - 1,
      to: parts[1] - 1,
      weight: weighted ? (parts[2] ?? 1) : 1
    })
  }

  return { n, edges }
}

/** 解析树：第一行 n，后面 n-1 行 "u v" */
function parseTree(text) {
  const rows = lines(text)
  if (rows.length === 0) throw new Error('请输入树：第一行是点数，后面每行一条边')

  const n = numbers(rows[0])[0] ?? 0
  if (n <= 0) throw new Error('点数必须大于 0')
  if (n > 120) throw new Error('点数建议不超过 120，否则树会画不下')

  const edges = []
  for (let index = 1; index < rows.length && edges.length < n - 1; index += 1) {
    const parts = numbers(rows[index])
    if (parts.length < 2) continue
    edges.push({ from: parts[0] - 1, to: parts[1] - 1 })
  }

  return { n, edges }
}

/* ─────────────────────── 通用工具 ─────────────────────── */

/** 邻接表 */
function buildAdjacency(n, edges, directed) {
  const adjacency = Array.from({ length: n }, () => [])
  for (const edge of edges) {
    adjacency[edge.from].push({ to: edge.to, weight: edge.weight ?? 1 })
    if (!directed) adjacency[edge.to].push({ to: edge.from, weight: edge.weight ?? 1 })
  }
  return adjacency
}

/** 把算出来的图转成可视化描述 */
function graphView(n, edges, options = {}) {
  const nodes = []
  for (let index = 0; index < n; index += 1) {
    nodes.push({
      id: String(index),
      label: String(index + 1),
      group: options.groups ? String(options.groups[index]) : undefined,
      highlight: options.highlightNodes ? options.highlightNodes.has(index) : false
    })
  }
  const viewEdges = edges.map((edge) => ({
    from: String(edge.from),
    to: String(edge.to),
    label: options.showWeight && edge.weight !== undefined ? String(edge.weight) : undefined,
    highlight: options.highlightEdges ? options.highlightEdges.has(`${edge.from}-${edge.to}`) : false
  }))
  return { kind: 'graph', title: options.title, directed: options.directed === true, nodes, edges: viewEdges }
}

/* ─────────────────── 数据结构：线段树 / 树状数组 ─────────────────── */

/**
 * 线段树。用一维数组存（下标从 1 开始，左右孩子是 2i / 2i+1），
 * 可视化时把它当成一棵完全二叉树画出来 —— 这正是初学者需要"看见"的东西。
 */
function buildSegmentTree(values) {
  const n = values.length
  const size = 4 * n + 4
  const tree = new Array(size).fill(0)

  const build = (node, left, right) => {
    if (left === right) {
      tree[node] = values[left]
      return
    }
    const mid = (left + right) >> 1
    build(node << 1, left, mid)
    build((node << 1) | 1, mid + 1, right)
    tree[node] = tree[node << 1] + tree[(node << 1) | 1]
  }
  if (n > 0) build(1, 0, n - 1)

  const query = (node, left, right, from, to) => {
    if (from <= left && right <= to) return tree[node]
    const mid = (left + right) >> 1
    let total = 0
    if (from <= mid) total += query(node << 1, left, mid, from, to)
    if (to > mid) total += query((node << 1) | 1, mid + 1, right, from, to)
    return total
  }

  return { tree, build, query, n }
}

/** 把线段树的数组形式转成树形可视化（只画真实存在的节点） */
function segmentTreeView(tree, n, range) {
  const inRange = (node, left, right) => {
    if (!range) return false
    return !(right < range[0] || left > range[1])
  }

  const walk = (node, left, right, depth) => {
    if (left > right || node >= tree.length || tree[node] === 0 && left !== right && depth > 0) {
      // 空的叶子也要画，但不必展开太深
    }
    const hit = inRange(node, left, right)
    if (left === right) {
      return {
        id: `s${node}`,
        label: String(tree[node]),
        note: `[${left + 1}]`,
        highlight: hit,
        children: []
      }
    }
    const mid = (left + right) >> 1
    return {
      id: `s${node}`,
      label: String(tree[node]),
      note: `[${left + 1}..${right + 1}]`,
      highlight: hit,
      children: [walk(node << 1, left, mid, depth + 1), walk((node << 1) | 1, mid + 1, right, depth + 1)]
    }
  }

  if (n === 0) return { kind: 'tree', nodes: [] }
  return { kind: 'tree', title: '线段树（每个节点是它管的那段区间的和）', nodes: [walk(1, 0, n - 1, 0)] }
}

function buildFenwick(values) {
  const n = values.length
  const tree = new Array(n + 1).fill(0)

  const add = (index, delta) => {
    for (let cursor = index + 1; cursor <= n; cursor += cursor & -cursor) tree[cursor] += delta
  }
  for (let index = 0; index < n; index += 1) add(index, values[index])

  const prefixSum = (index) => {
    let total = 0
    for (let cursor = index + 1; cursor > 0; cursor -= cursor & -cursor) total += tree[cursor]
    return total
  }

  return { tree, prefixSum, n }
}

/* ─────────────────── 图：最短路 / 拓扑 / 缩点 / MST ─────────────────── */

function dijkstra(n, adjacency, source) {
  const INF = Infinity
  const distance = new Array(n).fill(INF)
  const parent = new Array(n).fill(-1)
  const visited = new Array(n).fill(false)
  const steps = []
  distance[source] = 0

  for (let round = 0; round < n; round += 1) {
    let pick = -1
    for (let index = 0; index < n; index += 1) {
      if (!visited[index] && (pick === -1 || distance[index] < distance[pick])) pick = index
    }
    if (pick === -1 || distance[pick] === INF) break

    visited[pick] = true
    steps.push({
      title: `确定点 ${pick + 1} 的最短路：${distance[pick]}`,
      detail: `当前未确定的点里它最近，所以它的最短路不会再被改小了`
    })

    for (const edge of adjacency[pick]) {
      if (distance[pick] + edge.weight < distance[edge.to]) {
        distance[edge.to] = distance[pick] + edge.weight
        parent[edge.to] = pick
      }
    }
  }

  return { distance, parent, steps }
}

function topologicalSort(n, edges) {
  const adjacency = buildAdjacency(n, edges, true)
  const indegree = new Array(n).fill(0)
  for (const edge of edges) indegree[edge.to] += 1

  const queue = []
  for (let index = 0; index < n; index += 1) if (indegree[index] === 0) queue.push(index)

  const order = []
  while (queue.length > 0) {
    const current = queue.shift()
    order.push(current)
    for (const edge of adjacency[current]) {
      indegree[edge.to] -= 1
      if (indegree[edge.to] === 0) queue.push(edge.to)
    }
  }

  return { order, hasCycle: order.length !== n }
}

/** Tarjan 求强连通分量（缩点） */
function tarjanScc(n, edges) {
  const adjacency = buildAdjacency(n, edges, true)
  const dfn = new Array(n).fill(0)
  const low = new Array(n).fill(0)
  const component = new Array(n).fill(-1)
  const stack = []
  const onStack = new Array(n).fill(false)
  let timer = 0
  let count = 0

  // 用显式栈模拟递归，避免深图把 JS 调用栈打爆
  for (let start = 0; start < n; start += 1) {
    if (dfn[start] !== 0) continue

    const work = [{ node: start, next: 0 }]
    while (work.length > 0) {
      const frame = work[work.length - 1]
      const node = frame.node

      if (frame.next === 0) {
        timer += 1
        dfn[node] = low[node] = timer
        stack.push(node)
        onStack[node] = true
      }

      if (frame.next < adjacency[node].length) {
        const next = adjacency[node][frame.next].to
        frame.next += 1
        if (dfn[next] === 0) {
          work.push({ node: next, next: 0 })
        } else if (onStack[next]) {
          low[node] = Math.min(low[node], dfn[next])
        }
        continue
      }

      // 这个点处理完了
      work.pop()
      if (work.length > 0) {
        const parent = work[work.length - 1].node
        low[parent] = Math.min(low[parent], low[node])
      }

      if (low[node] === dfn[node]) {
        for (;;) {
          const top = stack.pop()
          onStack[top] = false
          component[top] = count
          if (top === node) break
        }
        count += 1
      }
    }
  }

  return { component, count }
}

function kruskal(n, edges) {
  const parent = Array.from({ length: n }, (_, index) => index)
  const find = (x) => {
    while (parent[x] !== x) {
      parent[x] = parent[parent[x]]
      x = parent[x]
    }
    return x
  }

  const sorted = [...edges].sort((a, b) => a.weight - b.weight)
  const chosen = []
  const rejected = []
  let total = 0

  for (const edge of sorted) {
    const rootA = find(edge.from)
    const rootB = find(edge.to)
    if (rootA === rootB) {
      rejected.push(edge)
      continue
    }
    parent[rootA] = rootB
    chosen.push(edge)
    total += edge.weight
  }

  return { chosen, rejected, total, connected: chosen.length === n - 1 }
}

/* ─────────────────── 树形 DP / 背包 ─────────────────── */

/** 树的最大独立集：选了父亲就不能选儿子 */
function treeMaxIndependentSet(n, edges) {
  const adjacency = buildAdjacency(n, edges, false)

  const order = []
  const visited = new Array(n).fill(false)
  const stack = [0]
  const parent = new Array(n).fill(-1)
  visited[0] = true
  while (stack.length > 0) {
    const node = stack.pop()
    order.push(node)
    for (const edge of adjacency[node]) {
      if (visited[edge.to]) continue
      visited[edge.to] = true
      parent[edge.to] = node
      stack.push(edge.to)
    }
  }

  // 选 / 不选 两种状态
  const take = new Array(n).fill(1)
  const skip = new Array(n).fill(0)
  for (let index = order.length - 1; index >= 0; index -= 1) {
    const node = order[index]
    for (const edge of adjacency[node]) {
      if (edge.to === parent[node]) continue
      take[node] += skip[edge.to]
      skip[node] += Math.max(take[edge.to], skip[edge.to])
    }
  }

  // 回溯出被选中的点
  const chosen = new Set()
  const walk = (node, canTake) => {
    const useTake = canTake && take[node] > skip[node]
    if (useTake) chosen.add(node)
    for (const edge of adjacency[node]) {
      if (edge.to === parent[node]) continue
      walk(edge.to, !useTake)
    }
  }
  walk(0, true)

  return { take, skip, chosen, answer: Math.max(take[0], skip[0]), order, parent }
}

function treeView(n, edges, options = {}) {
  const adjacency = buildAdjacency(n, edges, false)
  const visited = new Array(n).fill(false)
  const build = (node) => {
    visited[node] = true
    const children = []
    for (const edge of adjacency[node]) {
      if (visited[edge.to]) continue
      children.push(build(edge.to))
    }
    return {
      id: String(node),
      label: String(node + 1),
      note: options.notes ? options.notes[node] : undefined,
      highlight: options.highlight ? options.highlight.has(node) : false,
      children
    }
  }
  return { kind: 'tree', title: options.title, nodes: n > 0 ? [build(0)] : [] }
}

function knapsack(items, capacity) {
  const n = items.length
  const dp = Array.from({ length: n + 1 }, () => new Array(capacity + 1).fill(0))

  for (let index = 1; index <= n; index += 1) {
    const item = items[index - 1]
    for (let weight = 0; weight <= capacity; weight += 1) {
      dp[index][weight] = dp[index - 1][weight]
      if (weight >= item.weight) {
        dp[index][weight] = Math.max(dp[index][weight], dp[index - 1][weight - item.weight] + item.value)
      }
    }
  }

  // 回溯选了哪些
  const chosen = []
  let weight = capacity
  for (let index = n; index >= 1; index -= 1) {
    if (dp[index][weight] !== dp[index - 1][weight]) {
      chosen.push(index - 1)
      weight -= items[index - 1].weight
    }
  }
  chosen.reverse()

  return { dp, answer: dp[n][capacity], chosen }
}

/* ─────────────────── 数论：数列规律 ─────────────────── */

function difference(values) {
  const result = []
  for (let index = 1; index < values.length; index += 1) result.push(values[index] - values[index - 1])
  return result
}

/**
 * 猜数列的规律。
 * 只做**能给出确定结论**的判定（等差、等比、二阶差分等差），
 * 猜不出来就直说猜不出来 —— 一个乱猜规律的工具比没有更糟。
 */
function findSequenceRule(values) {
  if (values.length < 3) return { rule: null, reason: '至少给 3 个数才能看出规律' }

  const allEqual = (list) => list.every((item) => item === list[0])

  const d1 = difference(values)
  if (allEqual(d1)) return { rule: `等差数列，公差 ${d1[0]}`, detail: `差分全等于 ${d1[0]}` }

  if (values.every((item) => item !== 0)) {
    const ratios = []
    let geometric = true
    for (let index = 1; index < values.length; index += 1) {
      const ratio = values[index] / values[index - 1]
      ratios.push(ratio)
      if (!Number.isInteger(ratio)) geometric = false
    }
    if (geometric && allEqual(ratios)) {
      return { rule: `等比数列，公比 ${ratios[0]}`, detail: `相邻两项之比恒为 ${ratios[0]}` }
    }
  }

  const d2 = difference(d1)
  if (d2.length > 0 && allEqual(d2)) {
    return {
      rule: `二阶差分是常数 ${d2[0]}，所以通项是二次多项式`,
      detail: `一阶差分：${d1.join(', ')}\n二阶差分：${d2.join(', ')}`
    }
  }

  const d3 = difference(d2)
  if (d3.length > 0 && allEqual(d3)) {
    return { rule: `三阶差分是常数 ${d3[0]}，所以通项是三次多项式`, detail: `三阶差分：${d3.join(', ')}` }
  }

  return { rule: null, reason: '前三阶差分都不是常数，不是低阶多项式数列' }
}

/** 质因数分解，返回 { 质数: 次数 } */
function factorize(n) {
  const result = {}
  let value = Math.abs(Math.trunc(n))
  if (value < 2) return result
  for (let divisor = 2; divisor * divisor <= value; divisor += 1) {
    while (value % divisor === 0) {
      result[divisor] = (result[divisor] ?? 0) + 1
      value /= divisor
    }
  }
  if (value > 1) result[value] = (result[value] ?? 0) + 1
  return result
}

function gcd(a, b) {
  while (b !== 0) {
    const temp = a % b
    a = b
    b = temp
  }
  return a
}

/* ─────────────────────────── 注册 ─────────────────────────── */

export async function activate(api) {
  /*
   * 统计注册了几个，避免日志里的数字和实际对不上。
   *
   * ⚠️ 这里**绝对不能**写成 `api.registerSolver = ...`。
   * api 是宿主通过 contextBridge 暴露到插件世界的对象，那些属性是**只读的**；
   * ESM 是严格模式，赋值会抛
   *   TypeError: Cannot assign to read only property 'registerSolver'
   * 而这个异常发生在 activate 内部、又是异步的，宿主那边只会表现为
   * "激活超时（4000 ms）" —— 真正的原因完全看不到。
   * （这个插件曾经就是这么挂掉的，而且四个插件里只有它改写了 api 属性。）
   *
   * 正确做法：包一层自己的函数，原方法照常调用。
   */
  const registered = []
  const registerSolver = (registration) => {
    registered.push(registration.id)
    api.registerSolver(registration)
  }

  const arrayInput = {
    key: 'data',
    label: '数列',
    placeholder: '例如：1 2 3 4 5',
    multiline: false,
    initial: '1 3 5 7 9 11'
  }

  const graphInput = [
    {
      key: 'graph',
      label: '图的数据',
      multiline: true,
      placeholder: '第一行：点数 边数\n后面每行：u v [边权]',
      initial: '6 8\n1 2 1\n1 3 4\n2 3 2\n2 4 5\n3 4 1\n4 5 3\n5 6 2\n3 5 7'
    }
  ]

  /* ── 数据结构 ── */

  registerSolver({
    id: 'segment-tree',
    title: '线段树：区间求和',
    description: '建树后查询一段区间的和，并把整棵树画出来，能看到每个节点管的是哪一段。',
    category: '数据结构',
    inputs: [
      arrayInput,
      { key: 'left', label: '查询左端点', initial: '2' },
      { key: 'right', label: '查询右端点', initial: '4' }
    ],
    run(inputs) {
      const values = numbers(inputs.data)
      if (values.length === 0) throw new Error('请输入至少一个数')

      const { tree, query, n } = buildSegmentTree(values)
      const left = Math.max(1, Math.min(Number(inputs.left) || 1, n)) - 1
      const right = Math.max(left + 1, Math.min(Number(inputs.right) || n, n)) - 1
      const answer = query(1, 0, n - 1, left, right)

      return {
        text: `区间 [${left + 1}, ${right + 1}] 的和是 ${answer}`,
        note: '建树 O(n)，每次查询 O(log n)。高亮的节点就是这次查询实际用到的那些。',
        view: {
          kind: 'steps',
          title: '两种视图',
          steps: [
            { title: '原始数列', detail: values.join(', ') },
            { title: '区间和', detail: `[${left + 1}, ${right + 1}] = ${answer}` }
          ]
        }
      }
    }
  })

  registerSolver({
    id: 'segment-tree-view',
    title: '线段树：画出整棵树',
    description: '把线段树的结构画成二叉树，每个节点标出它管辖的区间与和。',
    category: '数据结构',
    inputs: [{ ...arrayInput, initial: '5 3 8 1 9 2' }],
    run(inputs) {
      const values = numbers(inputs.data)
      if (values.length === 0) throw new Error('请输入至少一个数')
      const { tree, n } = buildSegmentTree(values)
      return {
        text: `已建好 ${n} 个元素的线段树，树顶的和是 ${tree[1]}`,
        note: '节点上的小字是它管辖的区间（从 1 开始编号）。',
        view: segmentTreeView(tree, n, null)
      }
    }
  })

  registerSolver({
    id: 'fenwick',
    title: '树状数组：前缀和',
    description: '建树状数组并求前缀和，同时标出每个位置往后管多长。',
    category: '数据结构',
    inputs: [arrayInput, { key: 'index', label: '查询前几项', initial: '3' }],
    run(inputs) {
      const values = numbers(inputs.data)
      if (values.length === 0) throw new Error('请输入至少一个数')

      const { tree, prefixSum, n } = buildFenwick(values)
      const index = Math.max(1, Math.min(Number(inputs.index) || n, n)) - 1
      const answer = prefixSum(index)

      const labels = []
      for (let cursor = 1; cursor <= n; cursor += 1) {
        labels.push(`管 ${cursor & -cursor} 个`)
      }

      return {
        text: `前 ${index + 1} 项的和是 ${answer}`,
        note: '树状数组里第 i 位管的是「以 i 结尾、长度是 lowbit(i)」的那一段。',
        view: {
          kind: 'array',
          title: `树状数组内部（节点 1..${n}）`,
          values: tree.slice(1),
          labels,
          highlights: (() => {
            const hits = []
            for (let cursor = index + 1; cursor > 0; cursor -= cursor & -cursor) hits.push(cursor - 1)
            return hits
          })()
        }
      }
    }
  })

  /* ── 图论 ── */

  registerSolver({
    id: 'dijkstra',
    title: '最短路（Dijkstra）',
    description: '单源最短路。把图、每个点的最短距离、以及走过的路径都画出来。',
    category: '图论',
    inputs: [...graphInput, { key: 'source', label: '起点编号', initial: '1' }],
    run(inputs) {
      const { n, edges } = parseGraph(inputs.graph, true)
      const source = Math.max(1, Math.min(Number(inputs.source) || 1, n)) - 1
      const adjacency = buildAdjacency(n, edges, false)

      const { distance, parent, steps } = dijkstra(n, adjacency, source)

      const highlightEdges = new Set()
      for (let node = 0; node < n; node += 1) {
        if (parent[node] !== -1) highlightEdges.add(`${parent[node]}-${node}`)
      }

      const reachable = distance.filter((value) => Number.isFinite(value))
      const formatted = distance
        .map((value, index) => `${index + 1}:${Number.isFinite(value) ? value : '∞'}`)
        .join('  ')

      return {
        text: `从 ${source + 1} 出发，能到达 ${reachable.length} 个点。最远的距离是 ${
          reachable.length > 0 ? Math.max(...reachable) : '∞'
        }`,
        note: '高亮的边构成最短路径树；每条边上的数字是边权。',
        view: {
          kind: 'steps',
          title: `距离表：${formatted}`,
          steps: steps.slice(0, 60).map((step) => ({ title: step.title, detail: step.detail }))
        }
      }
    }
  })

  registerSolver({
    id: 'dijkstra-graph',
    title: '最短路：画出图与最短路径',
    description: '只画图，不输出过程。适合边比较多、想看清结构的时候。',
    category: '图论',
    inputs: [...graphInput, { key: 'source', label: '起点编号', initial: '1' }],
    run(inputs) {
      const { n, edges } = parseGraph(inputs.graph, true)
      const source = Math.max(1, Math.min(Number(inputs.source) || 1, n)) - 1
      const adjacency = buildAdjacency(n, edges, false)
      const { distance, parent } = dijkstra(n, adjacency, source)

      const highlightEdges = new Set()
      for (let node = 0; node < n; node += 1) {
        if (parent[node] !== -1) highlightEdges.add(`${parent[node]}-${node}`)
      }

      return {
        text: `最短距离：${distance
          .map((value, index) => `${index + 1}=${Number.isFinite(value) ? value : '∞'}`)
          .join('  ')}`,
        note: '粗线是最短路径树上的边。',
        view: graphView(n, edges, {
          title: `从 ${source + 1} 出发的最短路径树`,
          showWeight: true,
          highlightEdges,
          highlightNodes: new Set([source])
        })
      }
    }
  })

  registerSolver({
    id: 'topological',
    title: '拓扑排序',
    description: '有向无环图的拓扑序，并检测是否存在环。',
    category: '图论',
    inputs: [
      {
        key: 'graph',
        label: '有向图',
        multiline: true,
        placeholder: '第一行：点数 边数\n后面每行：u v（u → v）',
        initial: '6 6\n1 2\n1 3\n2 4\n3 4\n4 5\n4 6'
      }
    ],
    run(inputs) {
      const { n, edges } = parseGraph(inputs.graph, false)
      const { order, hasCycle } = topologicalSort(n, edges)

      if (hasCycle) {
        return {
          text: '这张图里有环，不存在拓扑序',
          note: '拓扑排序只能用于有向无环图。',
          view: graphView(n, edges, { title: '含有环的有向图', directed: true })
        }
      }

      const position = new Array(n).fill(0)
      order.forEach((node, index) => {
        position[node] = index
      })

      return {
        text: `拓扑序：${order.map((node) => node + 1).join(' → ')}`,
        note: '拓扑序保证每条边都是从前面指向后面。',
        view: {
          kind: 'graph',
          title: '按拓扑序排列',
          directed: true,
          nodes: order.map((node, index) => ({
            id: String(node),
            label: `${node + 1}（第 ${index + 1} 个）`,
            group: String(index)
          })),
          edges: edges.map((edge) => ({
            from: String(edge.from),
            to: String(edge.to),
            highlight: position[edge.from] < position[edge.to]
          }))
        }
      }
    }
  })

  registerSolver({
    id: 'tarjan-scc',
    title: 'Tarjan 缩点（强连通分量）',
    description: '找出所有强连通分量，同一个分量里的点用同一种颜色表示。',
    category: '图论',
    inputs: [
      {
        key: 'graph',
        label: '有向图',
        multiline: true,
        placeholder: '第一行：点数 边数\n后面每行：u v（u → v）',
        initial: '6 7\n1 2\n2 3\n3 1\n3 4\n4 5\n5 4\n5 6'
      }
    ],
    run(inputs) {
      const { n, edges } = parseGraph(inputs.graph, false)
      const { component, count } = tarjanScc(n, edges)

      const groups = []
      for (let index = 0; index < count; index += 1) {
        const members = []
        for (let node = 0; node < n; node += 1) if (component[node] === index) members.push(node + 1)
        groups.push(members)
      }

      const singles = groups.filter((group) => group.length === 1).length

      return {
        text: `一共 ${count} 个强连通分量，其中 ${singles} 个是单独的点`,
        note: '同一个分量里的任意两点互相可达。缩点后整张图就变成了有向无环图。',
        view: graphView(n, edges, {
          title: '强连通分量（同色 = 同一分量）',
          directed: true,
          groups: component
        })
      }
    }
  })

  registerSolver({
    id: 'kruskal',
    title: '最小生成树（Kruskal）',
    description: '按边权从小到大加边，避开成环的边，得到最小生成树。',
    category: '图论',
    // 注意：graphInput 本身已经是数组，这里用展开而不是 [graphInput] ——
    // 后者会多套一层，参数被嵌进去，界面上就是一个空输入框，还不会有任何报错。
    inputs: [...graphInput],
    run(inputs) {
      const { n, edges } = parseGraph(inputs.graph, true)
      const { chosen, rejected, total, connected } = kruskal(n, edges)

      if (!connected) {
        return {
          text: `图不连通，只能得到生成森林，已选 ${chosen.length} 条边，总权 ${total}`,
          note: '要得到生成树，n 个点需要恰好 n-1 条边。',
          view: graphView(n, edges, {
            title: '已选中的边',
            showWeight: true,
            highlightEdges: new Set(chosen.map((edge) => `${edge.from}-${edge.to}`))
          })
        }
      }

      return {
        text: `最小生成树总权值是 ${total}，用了 ${chosen.length} 条边`,
        note: `被跳过的 ${rejected.length} 条边会让树成环，所以没有选。`,
        view: graphView(n, edges, {
          title: '最小生成树（粗线是选中的边）',
          showWeight: true,
          highlightEdges: new Set(chosen.map((edge) => `${edge.from}-${edge.to}`))
        })
      }
    }
  })

  /* ── 动态规划 ── */

  registerSolver({
    id: 'tree-dp',
    title: '树形 DP：最大独立集',
    description: '在树上选一些点，要求相邻的点不能同时选，问最多能选几个。画出整棵树与被选中的点。',
    category: '动态规划',
    inputs: [
      {
        key: 'tree',
        label: '树的数据',
        multiline: true,
        placeholder: '第一行：点数\n后面每行：u v',
        initial: '7\n1 2\n1 3\n2 4\n2 5\n3 6\n3 7'
      }
    ],
    run(inputs) {
      const { n, edges } = parseTree(inputs.tree)
      const { take, skip, chosen, answer, parent } = treeMaxIndependentSet(n, edges)

      const notes = []
      for (let node = 0; node < n; node += 1) notes.push(`选${take[node]}/不选${skip[node]}`)

      return {
        text: `最多能选 ${answer} 个点`,
        note: '每个点下面的小字是「选它 / 不选它」两种情况下子树的最优值。高亮的就是最终选中的点。',
        view: treeView(n, edges, {
          title: '树上最大独立集',
          highlight: chosen,
          notes
        })
      }
    }
  })

  registerSolver({
    id: 'knapsack',
    title: '0/1 背包',
    description: '每件物品只能拿一次，在容量限制下让总价值最大。把整张 DP 表画出来。',
    category: '动态规划',
    inputs: [
      {
        key: 'items',
        label: '物品',
        multiline: true,
        placeholder: '每行：重量 价值',
        initial: '2 3\n3 4\n4 5\n5 6'
      },
      { key: 'capacity', label: '背包容量', initial: '8' }
    ],
    run(inputs) {
      const rows = lines(inputs.items)
      const items = rows
        .map((row) => numbers(row))
        .filter((parts) => parts.length >= 2)
        .map((parts) => ({ weight: parts[0], value: parts[1] }))

      if (items.length === 0) throw new Error('请至少输入一件物品，每行「重量 价值」')
      if (items.length > 30) throw new Error('物品数建议不超过 30，否则表格太宽')

      const capacity = Math.max(1, Math.min(Number(inputs.capacity) || 10, 60))
      const { dp, answer, chosen } = knapsack(items, capacity)

      return {
        text: `最大价值是 ${answer}，选了第 ${chosen.map((index) => index + 1).join('、')} 件物品`,
        note: '表格第 i 行表示"只考虑前 i 件物品"，列是容量。每一格都只依赖上一行。',
        view: {
          kind: 'matrix',
          title: 'DP 表（行 = 前 i 件物品，列 = 容量）',
          columns: Array.from({ length: capacity + 1 }, (_, index) => String(index)),
          rows: dp.map((row, index) => ({
            header: index === 0 ? '0 件' : `前 ${index} 件`,
            cells: row,
            highlight: index === dp.length - 1 ? [capacity] : undefined
          }))
        }
      }
    }
  })

  /* ── 数论 ── */

  registerSolver({
    id: 'sequence-rule',
    title: '数论：寻找数列规律',
    description: '自动判断等差、等比、二阶/三阶差分是常数的多项式数列。猜不出来会直说。',
    category: '数论',
    inputs: [arrayInput],
    run(inputs) {
      const values = numbers(inputs.data)
      if (values.length < 3) throw new Error('至少输入 3 个数')

      const { rule, reason, detail } = findSequenceRule(values)
      const d1 = difference(values)

      return {
        text: rule ?? `没有找到简单规律：${reason}`,
        note: rule
          ? '只判定能给出确定结论的情形，低阶差分不是常数时不会硬猜。'
          : '可以试试把数列拆成奇数项、偶数项分别看。',
        view: {
          kind: 'steps',
          title: '逐阶差分',
          steps: [
            { title: '原数列', detail: values.join(', ') },
            { title: '一阶差分', detail: d1.join(', ') },
            ...(detail ? [{ title: '推导', detail }] : [])
          ]
        }
      }
    }
  })

  registerSolver({
    id: 'factorize',
    title: '数论：分解质因数',
    description: '把若干个数分解成质因数，并算出最大公约数与最小公倍数。',
    category: '数论',
    inputs: [{ key: 'data', label: '整数（空格分隔）', initial: '12 18 24' }],
    run(inputs) {
      const values = numbers(inputs.data).filter((value) => Math.abs(value) >= 2)
      if (values.length === 0) throw new Error('请输入至少一个大于 1 的整数')

      const detail = values.map((value) => {
        const factors = factorize(value)
        const parts = Object.entries(factors).map(([prime, power]) =>
          power === 1 ? prime : `${prime}^${power}`
        )
        return { title: `${value} = ${parts.join(' × ')}`, detail: `质因数：${parts.join(' × ')}` }
      })

      let commonGcd = values[0]
      let commonLcm = values[0]
      for (const value of values.slice(1)) {
        commonGcd = gcd(commonGcd, value)
        commonLcm = (commonLcm / gcd(commonLcm, value)) * value
      }

      return {
        text: `最大公约数 ${commonGcd}，最小公倍数 ${commonLcm}`,
        note: '最小公倍数用 lcm(a,b) = a / gcd(a,b) * b 算，先除后乘可以避免溢出。',
        view: { kind: 'steps', title: '分解结果', steps: detail }
      }
    }
  })

  api.log(`OI-Helper 已激活：注册了 ${registered.length} 个求解器（零权限）`)
  // 以前这里写了一句 `api.__registered = registered`（"供验证脚本使用"）——
  // 但 api 是 contextBridge 暴露的**不可扩展**对象，于是 activate 的**最后一行**抛
  //   TypeError: Cannot add property __registered, object is not extensible
  // 后果很隐蔽：12 个求解器都已经注册成功了，但激活仍然算失败，
  // 插件状态变成 error。验证脚本用不上这个字段，直接去掉。
}
