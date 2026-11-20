'use strict';
'require view';
'require rpc';
'require poll';
'require ui';
'require xboxcapture.mrs as mrs';

const object = 'xbox-capture';
const status = rpc.declare({ object, method: 'status', raise: true });
const start = rpc.declare({
	object, method: 'start', params: ['name', 'interface', 'device', 'minutes', 'baseline_id'], raise: true
});
const stop = rpc.declare({ object, method: 'stop', raise: true });
const sessions = rpc.declare({ object, method: 'sessions', raise: true });
const get = rpc.declare({ object, method: 'get', params: ['id', 'offset'], raise: true });
const exportRules = rpc.declare({
	object, method: 'export', params: ['id', 'format', 'policy', 'omit', 'offset'], raise: true
});
const remove = rpc.declare({ object, method: 'remove', params: ['id'], raise: true });

const states = {
	recording: '录制中',
	stopping: '正在结束录制',
	stopped: '已结束',
	timeout: '已达时间上限',
	shutdown: '服务已停止',
	error: '录制异常'
};
const rowsPerPage = 40;
const baselineStates = new Set(['stopped', 'timeout', 'shutdown']);

function checked(response) {
	if (!response || typeof response !== 'object' || response.error)
		throw new Error(response && response.error || '录制服务返回了无效响应。');
	return response;
}

function button(text, handler, style) {
	return E('button', { type: 'button', class: 'btn cbi-button ' + (style || ''), click: handler }, [text]);
}

function field(text, input, hint) {
	return E('div', { class: 'cbi-value' }, [
		E('label', { class: 'cbi-value-title', for: input.id }, [text]),
		E('div', { class: 'cbi-value-field' }, [
			input, typeof hint === 'string' ? E('div', { class: 'cbi-value-description' }, [hint]) : hint || ''
		])
	]);
}

function errorNotice(error) {
	ui.addNotification(null, E('p', {}, [String(error.message || error)]), 'error');
}

function dateTime(seconds) {
	return new Date(seconds * 1000).toLocaleString();
}

function duration(seconds) {
	const minutes = Math.floor(Math.max(seconds, 0) / 60);
	return minutes + ' 分 ' + Math.max(seconds, 0) % 60 + ' 秒';
}

function counts(session) {
	return (session.baseline ? '新增 ' : '') + session.domain_count +
		' 个域名，' + session.ip_count + ' 个公网 IP';
}

return view.extend({
	handleSave: null,
	handleSaveApply: null,
	handleReset: null,

	render() {
		this.active = null;
		this.available = false;
		this.busy = false;
		this.request = 0;
		this.captureRevision = 0;
		this.baselines = new Map();

		const name = E('input', {
			id: 'xbox-game', type: 'text', maxlength: 64, required: true, placeholder: '例如 Forza Horizon 5'
		});
		this.captureMode = E('select', { id: 'xbox-mode' }, [
			E('option', { value: 'all' }, ['完整录制']),
			E('option', { value: 'new' }, ['只录新增'])
		]);
		this.baseline = E('select', { id: 'xbox-baseline', required: true, disabled: true }, [
			E('option', { value: '' }, ['选择一条完整录制'])
		]);
		this.baselineDetails = E('div', { class: 'cbi-value-description', role: 'status' });
		const baselineField = field('待机基线', this.baseline, this.baselineDetails);
		const device = E('input', {
			id: 'xbox-device', type: 'text', maxlength: 164, required: true,
			placeholder: '例如 00:11:22:33:44:55'
		});
		const iface = E('input', { id: 'xbox-iface', type: 'text', value: 'br-lan', maxlength: 15, required: true });
		const deviceField = field('Xbox 地址', device, '优先使用当前连接方式的 MAC 地址，以同时捕获 IPv4 和 IPv6。也可填写最多 4 个 IP，用逗号分隔。');
		const ifaceField = field('LAN 接口', iface, '填写 Xbox 所在的设备名，例如 br-lan 或 br-lan.20。');
		const minutes = E('input', { id: 'xbox-minutes', type: 'number', value: 120, min: 1, max: 360, required: true });
		this.startButton = E('button', {
			type: 'submit', class: 'btn cbi-button cbi-button-action', disabled: true
		}, ['开始录制']);
		this.stopButton = button('结束录制', () => this.changeCapture(() => stop()), 'cbi-button-remove');
		this.stopButton.disabled = true;
		this.statusText = E('p', { role: 'status' }, ['正在连接录制服务…']);
		this.history = E('div', {}, ['正在读取录制记录…']);
		this.detail = E('div', { class: 'cbi-section', hidden: true });

		const updateMode = () => {
			const onlyNew = this.captureMode.value === 'new';
			baselineField.hidden = !onlyNew;
			this.baseline.disabled = !onlyNew;
			deviceField.hidden = ifaceField.hidden = onlyNew;
			device.disabled = iface.disabled = onlyNew;
			this.updateBaselineDetails();
		};
		this.captureMode.addEventListener('change', updateMode);
		this.baseline.addEventListener('change', () => this.updateBaselineDetails());
		updateMode();

		const form = E('form', {
			submit: event => {
				event.preventDefault();
				if (this.startButton.disabled)
					return;
				if (this.captureMode.value === 'new')
					return this.changeCapture(() => start(name.value, undefined, undefined,
						Number(minutes.value), this.baseline.value));
				return this.changeCapture(() => start(name.value, iface.value.trim(), device.value, Number(minutes.value), ''));
			}
		}, [
			field('游戏或软件名称', name),
			field('录制模式', this.captureMode),
			deviceField,
			ifaceField,
			baselineField,
			field('最长录制时间（分钟）', minutes),
			E('p', {}, [this.startButton, ' ', this.stopButton]),
			this.statusText
		]);
		const root = E('div', {}, [
			E('h2', {}, ['Xbox 网络录制']),
			E('p', {}, ['先启动录制，再打开游戏。完成后结束录制，勾选需要导出的域名和 IP。']),
			E('div', { class: 'cbi-section' }, [form]),
			mrs.render(),
			E('div', { class: 'cbi-section' }, [
				E('h3', {}, ['录制记录']),
				E('p', {}, ['记录保存在路由器的临时存储中。重启路由器前请下载需要的规则。']),
				this.history
			]),
			this.detail
		]);

		poll.add(() => this.refresh(), 2);
		this.refresh();
		return root;
	},

	updateStatus(active, available) {
		this.active = active;
		this.available = available;
		const text = !available ? '录制服务未响应。'
			: !active ? '当前无录制。'
			: states[active.state] + ' · ' + active.name + ' · ' +
				duration(active.elapsed) + ' · ' + counts(active);
		if (this.statusText.textContent !== text)
			this.statusText.textContent = text;
		this.startButton.disabled = this.busy || !available || !!active ||
			(this.captureMode.value === 'new' && !this.baselines.has(this.baseline.value));
		this.stopButton.disabled = this.busy || !available || !active || active.state === 'stopping';
	},

	updateBaselineDetails() {
		const baseline = this.baselines.get(this.baseline.value);
		let message = '选择同一台 Xbox 在当前网络下的待机录制。';
		if (!this.baselines.size)
			message = '暂无可选基线。让 Xbox 停在主界面，用「完整录制」记录一段后台流量。';
		if (baseline) {
			message = '沿用 ' + baseline.interface + ' · ' + baseline.device + '。排除该录制中的 ' + counts(baseline) + '。';
			if (baseline.truncated || baseline.kernel_drops)
				message += ' 这份基线的抓包记录可能不完整。';
		}
		this.baselineDetails.textContent = message;
		this.updateStatus(this.active, this.available);
	},

	async refresh() {
		if (this.busy || this.refreshing)
			return;
		this.refreshing = true;
		const revision = this.captureRevision;
		try {
			const previous = this.active;
			const wasAvailable = this.available;
			const response = checked(await status());
			if (this.busy || revision !== this.captureRevision)
				return;
			this.updateStatus(response.active, true);
			if (!wasAvailable || !this.hasHistory || (previous && (!response.active || previous.id !== response.active.id)))
				await this.refreshHistory(previous && previous.id);
		} catch (error) {
			this.updateStatus(this.active, false);
			if (!this.hasHistory)
				this.history.textContent = error.message;
		} finally {
			this.refreshing = false;
		}
	},

	async changeCapture(operation) {
		if (this.busy)
			return;
		this.busy = true;
		this.captureRevision++;
		this.updateStatus(this.active, this.available);
		try {
			const previous = this.active;
			const response = checked(await operation());
			this.updateStatus(response.active, true);
			if (previous && !response.active)
				await this.refreshHistory(previous.id);
		} catch (error) {
			errorNotice(error);
		} finally {
			this.busy = false;
			this.updateStatus(this.active, this.available);
		}
	},

	async refreshHistory(finished) {
		const response = checked(await sessions());
		const selected = this.baseline.value;
		const eligible = response.sessions.filter(session => !session.baseline && baselineStates.has(session.state));
		this.baselines = new Map(eligible.map(session => [session.id, session]));
		this.baseline.replaceChildren(
			E('option', { value: '' }, ['选择一条完整录制']),
			...eligible.map(session => E('option', { value: session.id }, [session.name + ' · ' + dateTime(session.started)]))
		);
		this.baseline.value = this.baselines.has(selected) ? selected : '';
		this.updateBaselineDetails();
		if (!response.sessions.length) {
			this.history.textContent = '暂无录制记录。';
		} else {
			const rows = response.sessions.map(session => E('div', { class: 'tr' }, [
				E('div', { class: 'td' }, [session.name, E('br'), dateTime(session.started)]),
				E('div', { class: 'td' }, [states[session.state] + ' · ' + counts(session)]),
				E('div', { class: 'td cbi-section-actions' }, [
					button('查看与导出', () => this.openSession(session.id))
				])
			]));
			this.history.replaceChildren(E('div', { class: 'table' }, rows));
		}
		this.hasHistory = true;
		if (finished && response.sessions.some(session => session.id === finished))
			await this.openSession(finished);
	},

	async openSession(id) {
		const request = ++this.request;
		this.detail.hidden = false;
		this.detail.textContent = '正在读取录制…';
		try {
			let offset = 0;
			const entries = [];
			let response;
			do {
				response = checked(await get(id, offset));
				if (request !== this.request)
					return;
				entries.push(...response.entries);
				offset = response.next;
			} while (Number.isInteger(offset));
			this.drawSession(response.summary, entries);
		} catch (error) {
			if (request === this.request)
				this.detail.textContent = String(error.message || error);
		}
	},

	drawSession(session, entries) {
		const excluded = new Set();
		let page = 0;
		let exporting = false;
		const table = E('div', { class: 'table' });
		const paging = E('span');
		const selected = E('span', { role: 'status' });
		const search = E('input', { type: 'search', id: 'xbox-search', placeholder: '输入域名或 IP' });
		const searchType = E('select', { 'aria-label': '条目类型' }, [
			E('option', { value: 'all' }, ['全部']),
			E('option', { value: 'domain' }, ['域名']),
			E('option', { value: 'ip' }, ['IP'])
		]);
		const format = E('select', { id: 'xbox-format' }, [
			E('option', { value: 'provider' }, ['Classical 规则集']),
			E('option', { value: 'inline' }, ['Clash rules 配置'])
		]);
		const policy = E('input', { id: 'xbox-policy', value: 'Xbox', maxlength: 64 });
		const policyField = field('策略组', policy, '填写 Clash 配置中已有的策略组名称。');
		policyField.hidden = true;
		format.addEventListener('change', () => { policyField.hidden = format.value !== 'inline'; });

		const previous = button('上一页', () => { page--; drawRows(); });
		const next = button('下一页', () => { page++; drawRows(); });
		const indexed = entries.map((entry, index) => ({ entry, index }));
		const matches = () => {
			const query = search.value.trim().toLowerCase();
			return indexed.filter(({ entry }) => entry.value.includes(query) &&
				(searchType.value === 'all' || searchType.value === (entry.sources ? 'domain' : 'ip')));
		};
		const updateSelected = () => {
			selected.textContent = '已选 ' + (entries.length - excluded.size) + ' / ' + entries.length + ' 条';
			download.disabled = exporting || excluded.size === entries.length;
			mrsButton.disabled = excluded.size === entries.length;
		};
		const drawRows = () => {
			const matching = matches();
			const pages = Math.max(1, Math.ceil(matching.length / rowsPerPage));
			paging.textContent = (page + 1) + ' / ' + pages + ' 页';
			previous.disabled = page <= 0;
			next.disabled = page + 1 >= pages;
			const rows = matching.slice(page * rowsPerPage, (page + 1) * rowsPerPage).map(({ entry, index }) => {
				const choice = E('input', { type: 'checkbox', 'aria-label': '导出 ' + entry.value });
				choice.checked = !excluded.has(index);
				choice.addEventListener('change', () => {
					if (choice.checked)
						excluded.delete(index);
					else
						excluded.add(index);
					updateSelected();
				});
				return E('div', { class: 'tr' }, [
					E('label', { class: 'td', style: 'overflow-wrap:anywhere' }, [choice, ' ', entry.value]),
					E('div', { class: 'td' }, [entry.sources ? entry.sources.join(' / ') : entry.value.includes(':') ? 'IPv6' : 'IPv4'])
				]);
			});
			table.replaceChildren(...(rows.length ? rows : [E('p', {}, ['没有匹配的条目。'])]));
			updateSelected();
		};
		const resetPage = () => { page = 0; drawRows(); };
		search.addEventListener('input', resetPage);
		searchType.addEventListener('change', resetPage);

		const download = button('下载 YAML', async () => {
			exporting = true;
			updateSelected();
			try {
				await this.download(session.id, format.value, policy.value, selection());
			} catch (error) {
				errorNotice(error);
			} finally {
				exporting = false;
				updateSelected();
			}
		}, 'cbi-button-action');
		const selection = () => excluded.size ? entries.map((_, i) => excluded.has(i) ? '1' : '0').join('') : '';
		const mrsButton = button('导出或发布 MRS', () => mrs.fromRecording(session.name, session.id, selection()));
		const deleteButton = button('删除录制', () => this.confirmRemove(session), 'cbi-button-remove');

		const notes = [];
		if (session.error)
			notes.push(session.error);
		if (session.storage_warning)
			notes.push(session.storage_warning);
		if (session.truncated)
			notes.push('已达到去重条目上限，部分地址或域名未保存。');
		if (session.kernel_drops)
			notes.push('内核丢失了 ' + session.kernel_drops + ' 个抓包数据包。');

		this.detail.replaceChildren(
			E('h3', {}, [session.name]),
			E('p', {}, [session.interface + ' · ' + session.device]),
			...(session.baseline ? [E('p', {}, ['参照基线「' + session.baseline.name + '」'])] : []),
			E('p', {}, [dateTime(session.started) + ' · ' + duration(session.ended - session.started) +
				' · ' + states[session.state] + ' · ' + counts(session)]),
			...notes.map(note => E('p', { class: 'alert-message warning' }, [note])),
			field('筛选记录', search),
			E('p', {}, [
				searchType, ' ',
				button('选中匹配项', () => { matches().forEach(({ index }) => excluded.delete(index)); drawRows(); }), ' ',
				button('取消匹配项', () => { matches().forEach(({ index }) => excluded.add(index)); drawRows(); })
			]),
			table,
			E('p', {}, [previous, ' ', paging, ' ', next, ' · ', selected]),
			field('导出格式', format),
			policyField,
			E('p', {}, [download, ' ', mrsButton, ' ', deleteButton])
		);
		drawRows();
	},

	async download(id, format, policy, omit) {
		let offset = 0;
		let response;
		const parts = [];
		do {
			response = checked(await exportRules(id, format, policy, omit, offset));
			parts.push(response.yaml);
			offset = response.next;
		} while (Number.isInteger(offset));

		const href = URL.createObjectURL(new Blob(parts, { type: 'application/yaml;charset=utf-8' }));
		const link = E('a', { href, download: response.filename });
		document.body.appendChild(link);
		link.click();
		link.remove();
		window.setTimeout(() => URL.revokeObjectURL(href), 3000);
	},

	confirmRemove(session) {
		const confirm = button('删除', async () => {
			confirm.disabled = true;
			try {
				checked(await remove(session.id));
				ui.hideModal();
				++this.request;
				this.detail.hidden = true;
				await this.refreshHistory();
			} catch (error) {
				errorNotice(error);
				confirm.disabled = false;
			}
		}, 'cbi-button-remove');
		ui.showModal('删除录制', [
			E('p', {}, ['删除“' + session.name + '”的录制记录？']),
			E('div', { class: 'right' }, [button('取消', () => ui.hideModal()), ' ', confirm])
		]);
	}
});
