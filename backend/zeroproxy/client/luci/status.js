'use strict';
'require view';

/* Same-origin LuCI host: inherit its palette and let the outer page scroll.
 * No configuration, session token or proxy data crosses this bridge.
 */
return view.extend({
	render: function () {
		var frame = E('iframe', {
			src: '/cgi-bin/zeroproxy?embed=1',
			style: 'display:block;width:100%;min-width:0;height:640px;border:0;background:transparent',
			title: 'ZeroProxy 路由器管理'
		});
		var cleanup = function () {};
		frame.addEventListener('load', function () {
			cleanup();
			var doc;
			try { doc = frame.contentDocument; if (!doc || !doc.querySelector('.app-wrap')) return; }
			catch (e) { return; }
			var root = doc.documentElement, stopped = false, scheduled = 0;
			root.dataset.embedded = '1';
			function rgb(value) {
				var match = String(value).match(/^rgba?\(\s*([\d.]+)[, ]+([\d.]+)[, ]+([\d.]+)(?:\s*[,/]\s*([\d.]+))?\s*\)$/);
				return match && (match[4] === undefined || Number(match[4]) >= 0.9) ? match.slice(1,4).map(Number) : null;
			}
			function css(c) { return 'rgb(' + c.map(Math.round).join(',') + ')'; }
			function mix(a,b,t) { return a.map(function (v,i) { return v*(1-t)+b[i]*t; }); }
			function light(c) {
				var v = c.map(function (x) { x/=255; return x<=0.04045 ? x/12.92 : Math.pow((x+0.055)/1.055,2.4); });
				return v[0]*0.2126+v[1]*0.7152+v[2]*0.0722;
			}
			function contrast(a,b) { return (Math.max(light(a),light(b))+0.05)/(Math.min(light(a),light(b))+0.05); }
			function color(el,property) { return el && rgb(getComputedStyle(el)[property]); }
			function theme() {
				if (stopped || !frame.isConnected) return;
				var body = document.body, host = frame.parentElement;
				var background = color(body,'backgroundColor') || color(document.documentElement,'backgroundColor') || [245,246,248];
				var surface = null;
				for (var el=host; el && el!==body; el=el.parentElement) {
					surface = color(el,'backgroundColor'); if (surface) break;
				}
				var dark = light(surface || background)<0.2;
				var card = surface || (dark ? [32,35,43] : [255,255,255]);
				var text = color(body,'color') || (dark ? [230,233,240] : [45,50,58]);
				if (contrast(text,card)<4.5) text = dark ? [230,233,240] : [45,50,58];
				var accent = null, probe = document.createElement('span');
				probe.style.display='none'; body.appendChild(probe);
				var vars=['--primary','--primary-color','--main-color','--primary-color-high'];
				for (var i=0;i<vars.length;i++) {
					probe.style.color=''; probe.style.color='var('+vars[i]+')';
					var value=rgb(getComputedStyle(probe).color);
					if (value && Math.max.apply(null,value)-Math.min.apply(null,value)>35 && contrast(value,card)>2) { accent=value; break; }
				}
				probe.remove();
				if (!accent) {
					var controls=document.querySelectorAll('.cbi-button-apply,.cbi-button-positive,.btn-primary,.main-left .active > a,.main-left .nav-active > a,.sidebar .active > a');
					for (var j=0;j<controls.length;j++) {
						var bg=color(controls[j],'backgroundColor');
						if (bg && Math.max.apply(null,bg)-Math.min.apply(null,bg)>35 && contrast(bg,card)>2) { accent=bg; break; }
					}
				}
				accent=accent || (dark ? [137,160,255] : [94,114,228]);
				var sub=mix(text,card,0.2), border=mix(text,card,0.78), soft=mix(accent,card,0.92);
				var tokens={bg:card,card:card,'card-sub':mix(text,card,0.96),'card-hover':soft,text:text,sub:sub,muted:sub,border:border,'border-soft':mix(text,card,0.9),accent:accent,'accent-soft':soft,boost:accent,'boost-soft':soft,field:mix(text,card,0.97),'field-ink':text,'field-muted':sub,lime:accent,'accent-ink':contrast(accent,[255,255,255])>=4.5 ? [255,255,255] : [15,23,42]};
				root.dataset.theme=dark ? 'dark' : 'light';
				root.style.colorScheme=dark ? 'dark' : 'light';
				Object.keys(tokens).forEach(function (key) { root.style.setProperty('--'+key,css(tokens[key])); });
				// Typography follows the router, without inheriting an unusually large zoom/font.
				var font=getComputedStyle(body).fontFamily;
				root.style.setProperty('--host-font',font);
				resize();
			}
			function resize() {
				if (stopped || !frame.isConnected) return;
				// body min-height is zero in embed mode. Unlike document.scrollHeight,
				// this can shrink again after switching from logs to a shorter tab.
				var height=Math.ceil(doc.body.getBoundingClientRect().height);
				if (height>0 && Number.isFinite(height)) {
					var next=Math.max(240,Math.min(32768,height+2));
					if (Math.abs(parseFloat(frame.style.height)-next)>1) frame.style.height=next+'px';
				}
			}
			function queueTheme() {
				if (!frame.isConnected) { cleanup(); return; }
				if (!scheduled) scheduled=requestAnimationFrame(function () { scheduled=0; theme(); });
			}
			var changes=new MutationObserver(function (records) {
				if (!frame.isConnected) { cleanup(); return; }
				if (records.some(function (r) { return r.type==='attributes' && (r.target===document.documentElement || r.target!==frame && r.target.contains(frame)) || document.head.contains(r.target); })) queueTheme();
			});
			changes.observe(document.documentElement,{attributes:true});
			changes.observe(document.body,{attributes:true,childList:true,subtree:true});
			changes.observe(document.head,{childList:true,attributes:true,subtree:true});
			function stylesheetLoaded(event) { if (event.target.tagName==='LINK') queueTheme(); }
			document.addEventListener('load',stylesheetLoaded,true);
			var sizes=typeof ResizeObserver!=='undefined' ? new ResizeObserver(resize) : null;
			if (sizes) { sizes.observe(doc.body); sizes.observe(frame); }
			var media=window.matchMedia('(prefers-color-scheme: dark)');
			media.addEventListener('change',queueTheme);
			window.addEventListener('resize',queueTheme);
			cleanup=function () {
				stopped=true; changes.disconnect(); if(sizes)sizes.disconnect();
				if(scheduled)cancelAnimationFrame(scheduled);
				media.removeEventListener('change',queueTheme); window.removeEventListener('resize',queueTheme);
				document.removeEventListener('load',stylesheetLoaded,true);
			};
			theme();
		});
		return frame;
	},
	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
