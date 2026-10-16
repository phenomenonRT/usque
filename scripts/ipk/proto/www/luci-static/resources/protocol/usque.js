'use strict';
'require form';
'require network';
'require uci';
'require rpc';
'require ui';
'require poll';
'require dom';

/* Протокол netifd "usque": Cloudflare WARP (MASQUE) как интерфейс OpenWrt.
 * Серверная часть для панели состояния — rpcd-плагин /usr/libexec/rpcd/usque. */

var callInfo = rpc.declare({
	object: 'usque', method: 'info', params: [ 'iface', 'config' ], expect: { '': {} }
});
var callStart = rpc.declare({
	object: 'usque', method: 'start', params: [ 'iface' ], expect: { '': {} }
});
var callStop = rpc.declare({
	object: 'usque', method: 'stop', params: [ 'iface' ], expect: { '': {} }
});
var callRestart = rpc.declare({
	object: 'usque', method: 'restart', params: [ 'iface' ], expect: { '': {} }
});
var callCheck = rpc.declare({
	object: 'usque', method: 'check', params: [ 'iface' ], expect: { '': {} }
});
var callRegister = rpc.declare({
	object: 'usque', method: 'register', params: [ 'config', 'name', 'force' ], expect: { '': {} }
});

/* Панель, подсказки в полях и опрос запрашивают одно и то же состояние.
 * Общий кэш склеивает эти запросы: страница ждёт один ответ вместо трёх,
 * а запрос, который ещё выполняется, переиспользуется. */
var infoCache = { key: null, at: 0, p: null, done: false };

function callInfoShared(sid, cfg) {
	var key = sid + '\n' + cfg;
	var now = Date.now();
	if (infoCache.p && infoCache.key === key &&
	    (!infoCache.done || now - infoCache.at < 3000))
		return infoCache.p;

	var p = callInfo(sid, cfg);
	var entry = { key: key, at: now, p: p, done: false };
	infoCache = entry;
	p.then(function() {
		if (infoCache === entry) {
			entry.done = true;
			entry.at = Date.now();
		}
	}, function() {
		if (infoCache === entry)
			infoCache = { key: null, at: 0, p: null, done: false };
	});
	return p;
}

function dropInfoCache() {
	infoCache = { key: null, at: 0, p: null, done: false };
}

var DEFAULT_CONFIG = '/etc/usque/config.json';

network.registerPatternVirtual(/^usque-.+$/);

function cfgPath(sid) {
	return uci.get('network', sid, 'config') || DEFAULT_CONFIG;
}

function modeName(mode) {
	if (mode == 'bypass') return 'обход ТСПУ (перебор адресов)';
	return mode == 'h2' ? 'HTTP/2 (TCP)' : 'HTTP/3 QUIC (UDP)';
}

function profileName(p) {
	switch (p) {
	case 'quic': return 'только QUIC';
	case 'h2': return 'только HTTP/2';
	case 'manual': return 'вручную';
	default: return 'авто (обход ТСПУ)';
	}
}

/* Панель: состояние, «куда подключается», кнопки, регистрация и журнал. */
function statusBox(sid) {
	var box = E('div', { 'class': 'usque-status' });
	var logOpen = false;
	var regOut = '';
	var nameVal = '';
	var regOpen = false;
	var busy = false;
	var lastJson = null;

	function row(title, value) {
		return E('div', { 'style': 'margin:2px 0' }, [
			E('span', { 'style': 'display:inline-block;min-width:11em;color:#666' }, title),
			E('span', {}, value)
		]);
	}

	function btn(label, cls, handler, disabled) {
		return E('button', {
			'class': 'cbi-button ' + cls,
			'style': 'margin-right:.5em',
			'disabled': disabled ? true : null,
			'click': function(ev) {
				ev.preventDefault();
				if (busy) return;
				busy = true;
				ev.target.disabled = true;
				Promise.resolve(handler()).catch(function(e) {
					ui.addNotification(null, E('p', {}, 'usque: ' + (e && e.message ? e.message : e)), 'danger');
				}).then(function() {
					busy = false;
					dropInfoCache();
					return refresh(true);
				});
			}
		}, label);
	}

	function doRegister(nameInput, force) {
		regOut = 'Регистрация…';
		dropInfoCache();
		refresh(true);
		return callRegister(cfgPath(sid), nameInput.value || '', force ? 1 : 0).then(function(r) {
			regOut = (r.ok ? 'Готово.\n' : 'Не удалось (' + (r.code || '?') + ').\n') + (r.output || '');
		});
	}

	function render(info) {
		var connected = info.up && info.running;
		var state, color;
		var kids = [];

		if (connected) { state = 'Подключено'; color = '#2a9d3a'; }
		else if (info.running) { state = 'Подключаюсь…'; color = '#d98a00'; }
		else { state = 'Остановлено'; color = '#b33'; }

		kids.push(E('div', { 'style': 'font-size:120%;margin-bottom:.4em' }, [
			E('span', { 'style': 'color:' + color }, '● '),
			E('strong', {}, state),
			info.profile ? E('span', { 'style': 'color:#666' }, ' · способ: ' + profileName(info.profile)) : ''
		]));

		/* куда подключается */
		if (info.running && info.endpoint) {
			kids.push(row(connected ? 'Подключено к:' : 'Подключается к:', info.endpoint + ':' + info.port + ' · ' + modeName(info.mode)));
			kids.push(row('SNI:', info.sni || '—'));
		}
		else if (info.config_exists) {
			var ep = info.endpoint_v4 || info.endpoint_v6 || '—';
			var h2 = info.endpoint_h2_v4 || '162.159.198.2';
			kids.push(row('Сервер (QUIC, UDP):', ep + ' — из config.json'));
			kids.push(row('Сервер (HTTP/2, TCP):', h2 + ' — из config.json'));
		}
		/* чем именно поднялся обход: комбинация, подобранная перебором */
		if (info.bypass)
			kids.push(row('Обход ТСПУ идёт через:', info.bypass));
		if (info.bypass_saved)
			kids.push(row('Запомнено для следующего запуска:', info.bypass_saved));
		if (info.config_exists && (info.ipv4 || info.ipv6))
			kids.push(row('Адрес в тоннеле:', [ info.ipv4, info.ipv6 ].filter(Boolean).join(', ')));

		/* кнопки */
		var buttons = E('div', { 'style': 'margin:.6em 0' }, [
			btn('Старт', 'cbi-button-positive', function() { return callStart(sid); },
				info.running || !info.config_exists),
			btn('Стоп', 'cbi-button-negative', function() { return callStop(sid); }, false),
			btn('Перезапуск', 'cbi-button-action', function() { return callRestart(sid); },
				!info.config_exists),
			btn('Проверить', 'cbi-button-action', function() { return callCheck(sid); },
				!info.config_exists),
			btn('Обновить', 'cbi-button-neutral', function() { return Promise.resolve(); }, false)
		]);
		kids.push(buttons);

		/* результат кнопки «Проверить» (запускается в фоне, показывается по опросу) */
		if (info.check_running || info.check)
			kids.push(E('pre', {
				'style': 'white-space:pre-wrap;max-height:16em;overflow:auto;margin:.4em 0;background:#f6f6f6;padding:.4em;border-radius:3px'
			}, (info.check_running ? 'Проверка… (это может занять до минуты)\n' : '') + (info.check || '')));

		/* регистрация */
		var nameInput = E('input', {
			'type': 'text', 'class': 'cbi-input-text', 'placeholder': 'имя устройства (не обязательно)',
			'style': 'width:16em;margin-right:.5em', 'value': nameVal,
			'input': function(ev) { nameVal = ev.target.value; }
		});
		if (!info.config_exists) {
			kids.push(E('div', { 'style': 'margin:.6em 0;padding:.5em;border:1px solid #d98a00' }, [
				E('div', { 'style': 'margin-bottom:.4em' }, [
					E('strong', {}, 'Нет файла настроек WARP: '), cfgPath(sid),
					E('br'), 'Нажмите «Зарегистрировать» — создастся аккаунт Cloudflare WARP (принимаются условия Cloudflare). ',
					'Если из вашей сети регистрация не проходит, выполните её на другом компьютере и скопируйте config.json на роутер.'
				]),
				nameInput,
				btn('Зарегистрировать', 'cbi-button-positive', function() { return doRegister(nameInput, false); }, false)
			]));
		}
		else {
			kids.push(E('details', {
				'style': 'margin:.4em 0',
				'open': regOpen ? true : null,
				'toggle': function(ev) { regOpen = ev.target.open; }
			}, [
				E('summary', { 'style': 'cursor:pointer;color:#666' }, 'Перерегистрация'),
				E('div', { 'style': 'margin:.4em 0' }, [
					'Создаст новый аккаунт и перезапишет ' + cfgPath(sid) + ' (старый сохранится как .bak). ',
					E('br'),
					nameInput,
					btn('Перезаписать конфиг', 'cbi-button-negative', function() {
						if (!window.confirm('Перезаписать ' + cfgPath(sid) + ' новой регистрацией?')) return Promise.resolve();
						return doRegister(nameInput, true);
					}, false)
				])
			]));
		}
		if (regOut)
			kids.push(E('pre', { 'style': 'white-space:pre-wrap;margin:.4em 0' }, regOut));

		/* журнал */
		var log = E('details', {
			'style': 'margin-top:.4em',
			'open': logOpen ? true : null,
			'toggle': function(ev) { logOpen = ev.target.open; }
		}, [
			E('summary', { 'style': 'cursor:pointer;color:#666' }, 'Журнал usque'),
			E('pre', { 'style': 'white-space:pre-wrap;max-height:14em;overflow:auto;margin:.4em 0' },
				info.log || '(пусто)')
		]);
		kids.push(log);

		if (!connected && !info.running && info.log && /CONNECT|timeout|deadline/i.test(info.log))
			kids.push(E('div', { 'style': 'margin-top:.4em;color:#b33' },
				'Подключение не удалось. Выберите способ «Авто» или попробуйте другой порт / SNI ниже.'));

		dom.content(box, kids);
	}

	function refresh(force) {
		return callInfoShared(sid, cfgPath(sid)).then(function(info) {
			if (info && info.ok === false && info.code)
				throw new Error(info.code);
			/* Состояние не изменилось — дерево не пересобираем: не мигает
			 * и не теряется фокус в поле «имя устройства». */
			var json = JSON.stringify(info || {});
			if (!force && json === lastJson)
				return;
			lastJson = json;
			render(info || {});
		}).catch(function() {
			lastJson = null;
			dom.content(box, E('em', {},
				'Панель недоступна: выполните на роутере /etc/init.d/rpcd restart и войдите в LuCI заново.'));
		});
	}

	var tick = function() {
		if (!document.body.contains(box)) {
			poll.remove(tick);
			return;
		}
		if (busy) return;
		return refresh();
	};
	poll.add(tick, 5);
	refresh();

	return box;
}

return network.registerProtocol('usque', {
	getI18n: function() {
		return _('Cloudflare WARP (usque / MASQUE)');
	},

	getIfname: function() {
		return this._ubus('l3_device') || 'usque-%s'.format(this.sid);
	},

	getOpkgPackage: function() {
		return 'usque-proto';
	},

	isFloating: function() {
		return true;
	},

	isVirtual: function() {
		return true;
	},

	getDevices: function() {
		return null;
	},

	containsDevice: function(ifname) {
		return (network.getIfnameOf(ifname) == this.getIfname());
	},

	renderFormOptions: function(s) {
		var o;
		var durationRe = /^[0-9]+(ns|us|ms|s|m|h)?$/;

		/* адреса из config.json — как подсказки в полях */
		function withConfigHint(opt, fn) {
			opt.load = function(section_id) {
				var self = this;
				return callInfoShared(section_id, cfgPath(section_id)).then(function(info) {
					if (info) fn(self, info);
				}).catch(function() {}).then(function() {
					return form.Value.prototype.load.call(self, section_id);
				});
			};
		}

		/* ---------- Основные: состояние ---------- */

		o = s.taboption('general', form.DummyValue, '_status', _('Состояние'));
		o.cfgvalue = function() { return null; };
		o.renderWidget = function(section_id) {
			return statusBox(section_id);
		};

		o = s.taboption('general', form.Value, 'config', _('Файл настроек WARP'),
			_('Создаётся кнопкой «Зарегистрировать» выше или командой <code>usque -c файл register</code>. Содержит ключ устройства — никому не показывайте.'));
		o.placeholder = DEFAULT_CONFIG;
		o.optional = true;

		/* ---------- Основные: способ подключения ---------- */

		o = s.taboption('general', form.ListValue, 'profile', _('Способ подключения'),
			_('«Авто» включает обход ТСПУ: usque сам перебирает адреса, порты и SNI Cloudflare, пока соединение не поднимется. Ничего в сервере Cloudflare при этом не меняется.'));
		o.value('auto', _('Авто — обход ТСПУ, подобрать рабочую комбинацию (рекомендуется)'));
		o.value('quic', _('QUIC / HTTP/3 (UDP)'));
		o.value('h2', _('HTTP/2 (TCP 443) — если UDP режется'));
		o.value('manual', _('Вручную (параметры ниже)'));
		o.default = 'auto';
		o.rmempty = false;

		o = s.taboption('general', form.Value, 'connect_port', _('Порт сервера (UDP)'),
			_('Порт, который пробуется первым (основной 443; запасные 4443, 8443, 500, 4500, 1701, 8095). В режиме обхода usque затем сам перебирает и остальные порты, и SNI, и адреса сервера.'));
		o.value('443', '443 — основной');
		o.value('4443', '4443');
		o.value('8443', '8443');
		o.value('500', '500');
		o.value('4500', '4500');
		o.value('1701', '1701');
		o.value('8095', '8095');
		o.datatype = 'port';
		o.placeholder = '443';
		o.optional = true;

		o = s.taboption('general', form.Value, 'sni', _('SNI (имя в TLS-рукопожатии)'),
			_('Пусто — usque в режиме обхода сам перебирает имена: сначала вне Cloudflare, затем имена Cloudflare. Если задать своё, перебор SNI отключается и используется только оно.'));
		o.value('www.microsoft.com', 'www.microsoft.com — вне Cloudflare, обход начинает с таких имён');
		o.value('www.apple.com', 'www.apple.com — вне Cloudflare');
		o.value('www.bing.com', 'www.bing.com — вне Cloudflare');
		o.value('consumer-masque.cloudflareclient.com', 'consumer-masque.cloudflareclient.com — стандартный');
		o.value('zt-masque.cloudflareclient.com', 'zt-masque.cloudflareclient.com — рекомендует автор usque');
		o.value('www.cloudflare.com', 'www.cloudflare.com — обычный сайт');
		o.value('one.one.one.one', 'one.one.one.one — обычный сайт');
		o.placeholder = 'consumer-masque.cloudflareclient.com';
		o.optional = true;

		o = s.taboption('general', form.Value, 'endpoint', _('Адрес сервера Cloudflare (QUIC)'),
			_('IP, к которому идёт QUIC. Пусто — адрес из config.json. В режиме обхода пробуется первым, затем запасные адреса Cloudflare. Для MASQUE Cloudflare указывает сеть 162.159.197.0/24.'));
		o.datatype = 'ipaddr';
		o.optional = true;
		withConfigHint(o, function(self, info) {
			self.placeholder = (info.endpoint_v4 || '162.159.197.x') + ' (из config.json)';
		});

		o = s.taboption('general', form.Value, 'endpoint_h2', _('Адрес сервера Cloudflare (HTTP/2)'),
			_('IP, к которому идёт HTTP/2 по TCP. Пусто — адрес из config.json (по умолчанию 162.159.198.2). В режиме обхода пробуется вместе с остальными.'));
		o.datatype = 'ipaddr';
		o.optional = true;
		withConfigHint(o, function(self, info) {
			self.placeholder = (info.endpoint_h2_v4 || '162.159.198.2') + ' (из config.json)';
		});

		o = s.taboption('general', form.Flag, 'http2', _('Использовать HTTP/2 вместо QUIC'),
			_('Только для способа «Вручную».'));
		o.default = o.disabled;
		o.rmempty = false;
		o.depends('profile', 'manual');

		o = s.taboption('general', form.Flag, 'ipv6', _('Подключаться к серверу по IPv6'));
		o.default = o.disabled;
		o.rmempty = false;

		/* ---------- Дополнительно ---------- */

		o = s.taboption('advanced', form.Flag, 'tunnel_ipv4', _('IPv4 внутри тоннеля'));
		o.default = o.enabled;
		o.rmempty = false;

		o = s.taboption('advanced', form.Flag, 'tunnel_ipv6', _('IPv6 внутри тоннеля'));
		o.default = o.enabled;
		o.rmempty = false;

		o = s.taboption('advanced', form.Value, 'mtu', _('MTU тоннеля'),
			_('Менять не рекомендуется.'));
		o.datatype = 'range(1280,1500)';
		o.placeholder = '1280';
		o.optional = true;

		o = s.taboption('advanced', form.Value, 'keepalive', _('Период keepalive'),
			_('Секунды или длительность, например <code>30s</code>.'));
		o.placeholder = '30s';
		o.optional = true;
		o.validate = function(section_id, value) {
			if (value == null || value == '' || durationRe.test(value))
				return true;
			return _('Нужно число секунд или длительность вида 30s');
		};

		o = s.taboption('advanced', form.Value, 'reconnect_delay', _('Пауза перед переподключением'));
		o.placeholder = '1s';
		o.optional = true;
		o.validate = function(section_id, value) {
			if (value == null || value == '' || durationRe.test(value))
				return true;
			return _('Нужно число секунд или длительность вида 1s');
		};

		o = s.taboption('advanced', form.Value, 'initial_packet_size', _('Размер первого пакета'),
			_('Размер первого QUIC-пакета в байтах. Пусто — авто. В режиме обхода по умолчанию используется безопасный 1200.'));
		o.datatype = 'range(1200,1500)';
		o.placeholder = _('авто');
		o.optional = true;

		o = s.taboption('advanced', form.Flag, 'bypass', _('Обход ТСПУ и для выбранного способа'),
			_('«Авто» включает обход всегда. Включите здесь, чтобы и при явном способе usque перебирал адреса, порты и SNI Cloudflare и дробил TLS-рукопожатие.'));
		o.default = o.disabled;
		o.rmempty = false;
		o.depends('profile', 'quic');
		o.depends('profile', 'h2');
		o.depends('profile', 'manual');

		o = s.taboption('advanced', form.Flag, 'bypass_remember', _('Запоминать рабочую комбинацию обхода'),
			_('Удачная комбинация (адрес, порт, SNI, транспорт) сохраняется рядом с config.json, и следующее подключение начинается сразу с неё, без перебора. Работает в режиме обхода ТСПУ, в том числе после перезагрузки роутера.'));
		o.default = o.enabled;
		o.rmempty = false;

		o = s.taboption('advanced', form.Value, 'bypass_sni', _('Свои SNI для обхода'),
			_('Имена через пробел или запятую. Полностью заменяют встроенный список SNI. Нужны, когда провайдер блокирует домены Cloudflare по имени: сертификат сервера проверяется по ключу, поэтому подойдёт любое незаблокированное имя.'));
		o.placeholder = 'www.example.com';
		o.optional = true;

		o = s.taboption('advanced', form.Value, 'connect_timeout', _('Ожидание подключения (секунды)'),
			_('Сколько всего ждать, пока тоннель поднимется. Пусто: 90 с в режиме обхода, 20 с в остальных.'));
		o.datatype = 'uinteger';
		o.placeholder = '90';
		o.optional = true;

		o = s.taboption('advanced', form.Flag, 'insecure', _('Не проверять сертификат сервера'),
			_('Только для отладки.'));
		o.default = o.disabled;
		o.rmempty = false;

		o = s.taboption('advanced', form.Value, 'args', _('Дополнительные аргументы'),
			_('Передаются в <code>usque nativetun</code>.'));
		o.optional = true;
	}
});
