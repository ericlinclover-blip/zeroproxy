'use strict';
/* LuCI 菜单里的那一页。
 *
 * 真正的界面是 /www/zeroproxy/ 下的静态页面 (原生 JS, 与面板同一套卡片风格)。
 * 这里只做一件事: 用 LuCI 自己的登录态把它框进来 —— 于是"能不能打开这个管理面"
 * 由 LuCI 的 root 登录决定, 我们不用也不该再发明一套认证。
 */
'require view';

return view.extend({
	render: function () {
		return E('iframe', {
			src: '/zeroproxy/',
			style: 'width:100%;height:78vh;border:0;border-radius:10px;background:transparent',
			title: 'ZeroProxy'
		});
	},
	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
