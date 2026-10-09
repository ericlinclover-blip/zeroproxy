/** 引导令牌 (?token=…) 在本标签页里的驻留。
 *
 *  为什么不能只认地址栏那一次: 令牌一进页面就被从地址栏抹掉 (它是一次性凭据,
 *  不该长期留在历史 / 截图里), 而用户在这一步遇到的刷新是**常态** —— 引导阶段
 *  走的是自签证书, 浏览器先拦一页「您的连接不是私密连接」, 用户点过之后页面还会
 *  因为各种原因重载一次; 也别提用户自己按 F5。地址栏里没有令牌之后, 初始化页只剩
 *  一句「请用带 ?token= 的链接打开本页」, 而那条链接在终端里, 多半已经滚没了 ——
 *  于是"打不开初始化页"。
 *
 *  所以: 进页面时把令牌记进 sessionStorage (只活到本标签页关掉), 刷新时读回来;
 *  初始化成功后再清掉。地址栏仍然照旧抹干净。
 */
const TOKEN_KEY = "zp-bootstrap";

export function rememberToken(token) {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
  } catch (e) { /* 隐私模式下 sessionStorage 不可用: 退回"只认地址栏" */ }
}

export function readToken() {
  try {
    return sessionStorage.getItem(TOKEN_KEY) || "";
  } catch (e) {
    return "";
  }
}

/** 初始化成功后调用: 令牌已经作废 (服务端会立刻删除), 本标签页也不用再记着。 */
export function forgetToken() {
  try {
    sessionStorage.removeItem(TOKEN_KEY);
  } catch (e) { /* 同上 */ }
}
