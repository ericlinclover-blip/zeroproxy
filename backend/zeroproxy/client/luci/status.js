'use strict';
'require view';

/* app.js owns theme/sizing so it also repairs cached, older LuCI wrappers. */
return view.extend({
	render: function () {
		return E('iframe', {
			src: '/cgi-bin/zeroproxy?embed=1',
			style: 'display:block;width:100%;min-width:0;height:640px;border:0;background:transparent',
			title: 'ZeroProxy 路由器管理'
		});
	},
	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
