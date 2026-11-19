/**
 * 示例插件：排序可视化（插件开发教程第 7 节）。
 *
 * 演示两件事：
 *   1. 注册求解器、接收用户输入、返回可视化结果
 *   2. 同一个插件里注册多个求解器
 *
 * 全程零权限 —— 纯计算，不读文件、不联网。
 */

/** "1 2 3" / "1,2,3" / 多行 都行 */
function parseNumbers(text) {
  const matches = String(text ?? '').match(/-?\d+/g)
  return matches ? matches.map(Number) : []
}

export async function activate(api) {
  api.registerSolver({
    id: 'bubble-sort',
    title: '冒泡排序：看每一步',
    description: '把每一轮比较和交换都列出来，最后一轮单独画出结果。',
    category: '排序',
    inputs: [
      {
        key: 'data',
        label: '要排序的数列',
        placeholder: '例如：5 3 8 1',
        initial: '5 3 8 1 9 2'
      }
    ],
    run(inputs) {
      const original = parseNumbers(inputs.data)
      if (original.length === 0) {
        throw new Error('请先输入几个整数，例如：5 3 8 1')
      }
      if (original.length > 200) {
        throw new Error('数列太长了，最多 200 个数')
      }

      const arr = [...original]
      const steps = []
      let swaps = 0

      for (let i = 0; i < arr.length - 1; i++) {
        let changed = false
        for (let j = 0; j < arr.length - 1 - i; j++) {
          if (arr[j] > arr[j + 1]) {
            const tmp = arr[j]
            arr[j] = arr[j + 1]
            arr[j + 1] = tmp
            swaps++
            changed = true
            steps.push({
              title: `第 ${i + 1} 轮：交换位置 ${j + 1} 和 ${j + 2}`,
              detail: `→ ${arr.join(' ')}`
            })
          }
        }
        if (!changed) {
          steps.push({
            title: `第 ${i + 1} 轮：没有发生交换，说明已经有序`,
            detail: `→ ${arr.join(' ')}`
          })
          break
        }
      }

      return {
        text: `排序完成：${arr.join(' ')}（共交换 ${swaps} 次）`,
        view: { kind: 'steps', title: '每一轮发生了什么', steps },
        note: '冒泡排序每次把最大的元素"冒"到末尾，时间复杂度 O(n²)。'
      }
    }
  })

  api.registerSolver({
    id: 'sort-result',
    title: '只看排序结果（数组视图）',
    description: '把排好序的结果画成数组，高亮最小值的位置。',
    category: '排序',
    inputs: [{ key: 'data', label: '数列', initial: '5 3 8 1 9 2' }],
    run(inputs) {
      const arr = parseNumbers(inputs.data)
      if (arr.length === 0) throw new Error('请先输入数列')

      const sorted = [...arr].sort((a, b) => a - b)
      const minValue = Math.min(...arr)
      const minIndex = sorted.indexOf(minValue)

      return {
        text: `最小值是 ${minValue}，最大值是 ${Math.max(...arr)}`,
        view: {
          kind: 'array',
          title: '排序结果',
          values: sorted,
          highlights: minIndex >= 0 ? [minIndex] : []
        }
      }
    }
  })

  api.log('排序可视化已激活（2 个求解器）')
}
