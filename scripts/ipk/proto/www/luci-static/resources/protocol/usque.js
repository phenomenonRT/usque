'use strict';
'require form';
'require network';

network.registerPatternVirtual(/^usque-.+$/);

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

		/* --- General Settings --- */

		o = s.taboption('general', form.Value, 'config', _('Config file'),
			_('Created by <code>usque -c &lt;file&gt; register</code>.'));
		o.placeholder = '/etc/usque/config.json';
		o.optional = true;

		o = s.taboption('general', form.Flag, 'defaultroute', _('Use as default route'),
			_('Send all router traffic through WARP. The route to the Cloudflare endpoint is added via the previous gateway automatically.'));
		o.default = o.disabled;
		o.rmempty = false;

		o = s.taboption('general', form.Value, 'metric', _('Route metric'));
		o.datatype = 'uinteger';
		o.placeholder = '0';
		o.optional = true;
		o.depends('defaultroute', '1');

		o = s.taboption('general', form.DynamicList, 'dns', _('Use custom DNS servers'));
		o.datatype = 'ipaddr';
		o.placeholder = '1.1.1.1';
		o.optional = true;

		/* --- Advanced Settings --- */

		o = s.taboption('advanced', form.Flag, 'http2', _('Use HTTP/2 (TCP) instead of HTTP/3 (QUIC)'),
			_('Helps when UDP is blocked.'));
		o.default = o.disabled;
		o.rmempty = false;

		o = s.taboption('advanced', form.Flag, 'ipv6', _('Connect to the endpoint over IPv6'));
		o.default = o.disabled;
		o.rmempty = false;

		o = s.taboption('advanced', form.Value, 'connect_port', _('Endpoint port'));
		o.datatype = 'port';
		o.placeholder = '443';
		o.optional = true;

		o = s.taboption('advanced', form.Value, 'sni', _('SNI'));
		o.placeholder = _('usque default');
		o.optional = true;

		o = s.taboption('advanced', form.Flag, 'tunnel_ipv4', _('IPv4 inside the tunnel'));
		o.default = o.enabled;
		o.rmempty = false;

		o = s.taboption('advanced', form.Flag, 'tunnel_ipv6', _('IPv6 inside the tunnel'));
		o.default = o.enabled;
		o.rmempty = false;

		o = s.taboption('advanced', form.Value, 'mtu', _('Tunnel MTU'),
			_('Changing the default is not recommended.'));
		o.datatype = 'range(1280,1500)';
		o.placeholder = '1280';
		o.optional = true;

		o = s.taboption('advanced', form.Value, 'keepalive', _('Keepalive period'),
			_('Seconds or a duration such as <code>30s</code>.'));
		o.placeholder = '30s';
		o.optional = true;
		o.validate = function(section_id, value) {
			if (value == null || value == '' || durationRe.test(value))
				return true;
			return _('Expected a number of seconds or a duration like 30s');
		};

		o = s.taboption('advanced', form.Value, 'reconnect_delay', _('Reconnect delay'));
		o.placeholder = '1s';
		o.optional = true;
		o.validate = function(section_id, value) {
			if (value == null || value == '' || durationRe.test(value))
				return true;
			return _('Expected a number of seconds or a duration like 1s');
		};

		o = s.taboption('advanced', form.Value, 'initial_packet_size', _('Initial packet size'));
		o.datatype = 'range(1200,1500)';
		o.placeholder = _('auto');
		o.optional = true;

		o = s.taboption('advanced', form.Value, 'connect_timeout', _('Connect timeout (seconds)'),
			_('How long to wait for the tunnel when the interface starts.'));
		o.datatype = 'uinteger';
		o.placeholder = '20';
		o.optional = true;

		o = s.taboption('advanced', form.Flag, 'insecure', _('Do not verify the endpoint certificate'),
			_('For debugging only.'));
		o.default = o.disabled;
		o.rmempty = false;

		o = s.taboption('advanced', form.Value, 'args', _('Extra arguments'),
			_('Passed to <code>usque nativetun</code>.'));
		o.optional = true;
	}
});
