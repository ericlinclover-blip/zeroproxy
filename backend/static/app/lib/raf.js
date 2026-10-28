/** 渲染调度器: 把多次 DOM 更新合并到同一个 rAF 批次里。
 *
 *  问题: 20s 轮询 + 操作回调会频繁触发 renderDash(), 每次都做 innerHTML 全量
 *  替换 → 页面闪烁。
 *
 *  方案: 用 requestAnimationFrame 做批次合并。
 *    - renderDash 排进队列, rAF 触发时一次性执行。
 *    - 如果队列里有多个 renderDash, 只执行最新的那一次。
 *    - 操作后的刷新会"吞掉"定时轮询的刷新, 页面只闪一次。
 *
 *  用法:
 *    queueRender(renderDash, { replace: true })  // 仪表盘全量重绘
 *    queueRender(updateNodeCard)                   // 单节点局部更新
 */

// 排队的渲染函数列表。
const queue = [];
let scheduled = false;
let replaced = false;   // 当前批次是否有 replace=true 的任务

/** 注册一个渲染函数。
 *  { replace: true } = 这会刷新整个仪表盘, 清掉队列里旧的 renderDash。 */
export function queueRender(fn, opts = {}) {
  if (opts.replace) {
    // 清除队列里所有旧的 replace=true 标记项
    for (let i = queue.length - 1; i >= 0; i--) {
      if (queue[i].replace) queue.splice(i, 1);
    }
    replaced = true;
  }
  queue.push({ fn, replace: !!opts.replace });

  if (!scheduled) {
    scheduled = true;
    requestAnimationFrame(() => {
      scheduled = false;
      const batch = [...queue];
      queue.length = 0;
      // 执行时按原始函数执行 (去掉 replace 包装)
      batch.forEach(({ fn }) => { try { fn(); } catch (e) { /* 一个失败不影响其他 */ } });
    });
  }
}

/** 立即清空队列 (用于手动"刷新"按钮)。 */
export function flushQueue() {
  if (!scheduled) return;
  // rAF 已经在跑了, 等它执行
}

/** 检查队列是否为空。 */
export function isQueueEmpty() {
  return queue.length === 0;
}
