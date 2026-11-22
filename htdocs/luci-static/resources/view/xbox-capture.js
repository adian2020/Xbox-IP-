'use strict';
'require view';
'require rpc';
'require poll';
'require ui';
'require xboxcapture.mrs as mrs';
'require xboxcapture.monitor as monitor';
'require xboxcapture.asn as asn';

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
const removeMany = rpc.declare({ object, method: 'remove_many', params: ['ids'], raise: true });

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
	return E('button', { type: 'button', class: 'xbox-button ' + (style || ''), click: handler }, [text]);
}

function field(text, input, hint, wide, control = input) {
	return E('div', { class: 'xbox-field' + (wide ? ' xbox-field-wide' : '') }, [
		E('label', { for: input.id }, [text]),
		control,
		typeof hint === 'string' ? E('small', { class: 'xbox-muted' }, [hint]) : hint || ''
	]);
}

function statusBadge(state, label) {
	return E('span', { class: 'xbox-badge', 'data-state': state }, [label]);
}

function metric(value, title) {
	return E('div', { class: 'xbox-metric' }, [value, E('span', {}, [title])]);
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

function captureHint(session) {
	if (session.packet_count === 0) {
		if (session.frame_count)
			return '已收到链路层报文，尚未识别到 Xbox 的 IPv4 或 IPv6 报文。请在主机上运行「测试网络连接」。';
		return '还没收到目标报文。确认地址后，在 Xbox 上运行「测试网络连接」。若当前 LAN 接口仍为 0，可试 any。';
	}
	if (session.fakeip_count && !session.ip_count)
		return '已收到 Fake-IP 流量（198.18.0.0/15）。这些地址会被排除在公网 IP 规则之外。';
	if (session.packet_count > 0 && !session.ip_count && !session.domain_count)
		return session.baseline
			? '已收到目标报文，当前没有基线之外的域名或公网 IP。'
			: '已收到目标报文，当前没有可导出的明文 DNS、TLS 域名或公网 IP。';
	return '';
}

return view.extend({
	handleSave: null,
	handleSaveApply: null,
	handleReset: null,

	render() {
		this.active = null;
		this.available = null;
		this.busy = false;
		this.request = 0;
		this.captureRevision = 0;
		this.baselines = new Map();
		this.selectedHistory = new Set();
		this.historyItems = [];
		this.historyChecks = new Map();
		this.historyRequest = 0;
		this.hasHistory = false;
		this.detailId = null;
		this.liveMonitor = monitor.captureMonitor(id => this.openSession(id, true));
		this.refreshOwnership = null;
		const ownership = asn.controls(() => this.refreshOwnership?.());

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
		this.baselineDetails = E('small', { class: 'xbox-muted', role: 'status' });
		const baselineField = field('待机基线', this.baseline, this.baselineDetails, true);
		const device = E('input', {
			id: 'xbox-device', type: 'text', maxlength: 164, required: true,
			placeholder: '例如 00:11:22:33:44:55'
		});
		const iface = E('input', { id: 'xbox-iface', type: 'text', value: 'br-lan', maxlength: 15, required: true });
		const deviceField = field('Xbox 地址', device, '可选择已发现的设备，也可填写 MAC 或局域网 IP。',
			true, monitor.devicePicker(device, iface));
		const ifaceField = field('LAN 接口', iface, '可填 br-lan、VLAN 接口或 any。');
		const minutes = E('input', { id: 'xbox-minutes', type: 'number', value: 120, min: 1, max: 360, required: true });
		this.startButton = E('button', {
			type: 'submit', class: 'xbox-button xbox-primary', disabled: true
		}, ['开始录制']);
		this.stopButton = button('结束录制', () => this.changeCapture(() => stop()), 'xbox-danger');
		this.stopButton.disabled = true;
		this.statusText = E('span', { role: 'status', class: 'xbox-badge' });
		this.liveName = E('strong', { class: 'xbox-live-name' });
		this.liveTime = E('span', { class: 'xbox-live-time' });
		this.liveSession = E('div', { class: 'xbox-live-session', hidden: true }, [this.liveName, this.liveTime]);
		this.packetValue = E('strong');
		this.domainValue = E('strong');
		this.ipValue = E('strong');
		this.captureText = E('p', { class: 'xbox-muted xbox-capture-note' });
		this.history = E('div', { class: 'xbox-muted' }, ['正在读取录制记录…']);
		this.detail = E('section', { class: 'xbox-panel xbox-detail', hidden: true, 'aria-label': '录制详情' });
		this.historyMaster = E('input', { type: 'checkbox', 'aria-label': '全选录制记录' });
		this.historySelection = E('span', { class: 'xbox-muted', role: 'status' });
		this.historySort = E('select', { 'aria-label': '录制排序' }, [
			E('option', { value: 'recent' }, ['最新优先']),
			E('option', { value: 'earliest' }, ['最早优先']),
			E('option', { value: 'name' }, ['名称排序'])
		]);
		this.historyDelete = button('删除所选', () => this.confirmRemove([...this.selectedHistory]), 'xbox-danger');
		this.historyMaster.addEventListener('change', () => {
			this.selectedHistory = new Set(this.historyMaster.checked ? this.historyChecks.keys() : []);
			this.updateHistorySelection();
		});
		this.historySort.addEventListener('change', () => this.drawHistory());
		this.updateHistorySelection();

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
			class: 'xbox-form',
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
			field('游戏或软件名称', name, null, true),
			deviceField,
			ifaceField,
			field('录制模式', this.captureMode),
			field('最长录制时间（分钟）', minutes),
			baselineField,
			E('div', { class: 'xbox-actions xbox-field-wide' }, [this.startButton, this.stopButton])
		]);
		const root = E('div', { id: 'xbox-capture' }, [
			E('link', { rel: 'stylesheet', href: L.resource('xboxcapture/capture.css') + '?v=1.5.0' }),
			E('header', { class: 'xbox-heading' }, [
				E('h2', {}, ['Xbox 网络录制']),
				E('p', { class: 'xbox-muted' }, ['先开始录制，再打开游戏。'])
			]),
			E('div', { class: 'xbox-overview' }, [
				E('section', { class: 'xbox-panel xbox-config' }, [E('h3', {}, ['录制设置']), form]),
				E('section', { class: 'xbox-panel xbox-live' }, [
					E('div', { class: 'xbox-panel-head' }, [E('h3', {}, ['实时状态']), this.statusText]),
					this.liveSession,
					E('div', { class: 'xbox-metrics' }, [
						metric(this.packetValue, '目标 IP 报文'),
						metric(this.domainValue, '域名'),
						metric(this.ipValue, '公网 IP')
					]),
					this.captureText,
					E('div', { class: 'xbox-live-actions' }, [this.liveMonitor.button, ownership.button]),
					ownership.message
				])
			]),
			this.liveMonitor.panel,
			E('section', { class: 'xbox-panel xbox-history' }, [
				E('div', { class: 'xbox-panel-head' }, [
					E('h3', {}, ['录制记录']),
					E('small', { class: 'xbox-muted' }, ['重启路由器前请下载所需规则'])
				]),
				E('div', { class: 'xbox-toolbar' }, [
					E('label', { class: 'xbox-check' }, [this.historyMaster, '全选']),
					this.historySelection,
					E('div', { class: 'xbox-toolbar-end' }, [this.historySort, this.historyDelete])
				]),
				this.history
			]),
			this.detail,
			E('details', { class: 'xbox-panel xbox-integrations' }, [
				E('summary', {}, ['GitHub 与 MRS']), mrs.render()
			])
		]);

		poll.add(() => this.refresh(), 2);
		poll.add(ownership.refresh, 2);
		this.refresh();
		return root;
	},

	updateStatus(active, available) {
		this.active = active;
		this.available = available;
		const text = available === null ? '连接中' : !available ? '服务未响应'
			: !active ? '待录制' : states[active.state];
		if (this.statusText.textContent !== text)
			this.statusText.textContent = text;
		this.statusText.setAttribute('data-state', available === false ? 'error' : active?.state || 'idle');
		this.liveSession.hidden = !active;
		this.liveName.textContent = active?.name ?? '';
		this.liveTime.textContent = active ? duration(active.elapsed) : '—';
		this.packetValue.textContent = active?.packet_count ?? '—';
		this.domainValue.textContent = active?.domain_count ?? '—';
		this.ipValue.textContent = active?.ip_count ?? '—';
		let hint = '';
		if (available && active && Number.isInteger(active.packet_count)) {
			const selector = active.capture_mac ? 'MAC ' + active.capture_mac : '当前填写的 IP';
			hint = '接口 ' + active.interface + ' · ' + selector;
			if (active.state === 'recording' && (active.elapsed >= 8 || active.packet_count)) {
				const explanation = captureHint(active);
				if (explanation)
					hint += '。' + explanation;
			}
		}
		this.captureText.textContent = hint;
		this.captureText.hidden = !hint;
		this.liveMonitor.update(active, available);
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
		const request = ++this.historyRequest;
		const response = checked(await sessions());
		if (request !== this.historyRequest)
			return;
		const selected = this.baseline.value;
		const eligible = response.sessions.filter(session => !session.baseline && baselineStates.has(session.state));
		this.baselines = new Map(eligible.map(session => [session.id, session]));
		this.baseline.replaceChildren(
			E('option', { value: '' }, ['选择一条完整录制']),
			...eligible.map(session => E('option', { value: session.id }, [session.name + ' · ' + dateTime(session.started)]))
		);
		this.baseline.value = this.baselines.has(selected) ? selected : '';
		this.updateBaselineDetails();
		this.historyItems = response.sessions;
		const known = new Set(response.sessions.map(session => session.id));
		this.selectedHistory = new Set([...this.selectedHistory].filter(id => known.has(id)));
		this.drawHistory();
		this.hasHistory = true;
		if (finished && known.has(finished))
			await this.openSession(finished);
	},

	drawHistory() {
		const items = [...this.historyItems];
		const sort = this.historySort.value;
		items.sort((a, b) => {
			if (sort === 'name')
				return a.name.localeCompare(b.name, 'zh-CN') || b.started - a.started;
			return sort === 'earliest' ? a.started - b.started : b.started - a.started;
		});
		this.historyChecks.clear();
		const rows = items.map(session => {
			const name = E('strong', { class: 'xbox-record-name' }, [session.name]);
			const input = E('input', { type: 'checkbox', 'aria-label': '选择 ' + session.name });
			const row = E('li', { class: 'xbox-record' }, [
				E('label', { class: 'xbox-record-label' }, [
					input,
					E('span', {}, [name, E('small', { class: 'xbox-muted' }, [dateTime(session.started)])])
				]),
				E('div', { class: 'xbox-record-info' }, [
					statusBadge(session.state, states[session.state]),
					E('small', { class: 'xbox-muted' }, [counts(session)])
				]),
				button('查看与导出', () => this.openSession(session.id, true), 'xbox-compact')
			]);
			input.addEventListener('change', () => {
				if (input.checked)
					this.selectedHistory.add(session.id);
				else
					this.selectedHistory.delete(session.id);
				this.updateHistorySelection();
			});
			this.historyChecks.set(session.id, { input, row });
			return row;
		});
		if (rows.length)
			this.history.replaceChildren(E('ul', { class: 'xbox-history-list' }, rows));
		else
			this.history.replaceChildren(E('p', { class: 'xbox-empty' }, ['暂无录制记录']));
		this.historySort.disabled = rows.length < 2;
		this.updateHistorySelection();
	},

	updateHistorySelection() {
		const count = this.selectedHistory.size;
		const total = this.historyChecks.size;
		this.historyMaster.disabled = !total;
		this.historyMaster.checked = total > 0 && count === total;
		this.historyMaster.indeterminate = count > 0 && count < total;
		this.historyDelete.disabled = !count;
		this.historySelection.textContent = '已选 ' + count + ' 条';
		for (const [id, { input, row }] of this.historyChecks) {
			input.checked = this.selectedHistory.has(id);
			row.classList.toggle('is-selected', input.checked);
		}
	},

	async readSession(id, request) {
		let offset = 0;
		const entries = [];
		let response;
		do {
			response = checked(await get(id, offset));
			if (request !== this.request)
				return null;
			entries.push(...response.entries);
			offset = response.next;
		} while (Number.isInteger(offset));
		return { summary: response.summary, entries };
	},

	async openSession(id, scroll = false) {
		const request = ++this.request;
		this.refreshOwnership = null;
		this.detailId = id;
		this.detail.hidden = false;
		this.detail.textContent = '正在读取录制…';
		if (scroll)
			this.detail.scrollIntoView({ block: 'start' });
		try {
			const result = await this.readSession(id, request);
			if (result && request === this.request)
				this.drawSession(result.summary, result.entries);
		} catch (error) {
			if (request === this.request)
				this.detail.textContent = String(error.message || error);
		}
	},

	drawSession(session, entries) {
		const excluded = new Set();
		let page = 0;
		let exporting = false;
		const table = E('div', { class: 'xbox-results', role: 'table', 'aria-label': '域名、IP 与端口' });
		const paging = E('span', { class: 'xbox-muted' });
		const selected = E('span', { class: 'xbox-muted', role: 'status' });
		const search = E('input', { type: 'search', id: 'xbox-search', placeholder: '搜索域名、IP、端口或归属' });
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
			return indexed.filter(({ entry }) =>
				(entry.value.includes(query) || asn.matchesOwner(entry, query) || entry.ports?.some(([protocol, port]) =>
					(protocol.toLowerCase() + ' ' + port).includes(query))) &&
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
				const source = entry.sources ? entry.sources.join(' / ') : entry.value.includes(':') ? 'IPv6' : 'IPv4';
				const ports = monitor.ports(entry);
				return E('div', { class: 'xbox-result-row', role: 'row' }, [
					E('div', { role: 'cell' }, [
						E('label', { class: 'xbox-result-label' }, [choice,
							E('span', {}, [E('span', { class: 'xbox-target' }, [entry.value]),
								E('small', { class: 'xbox-muted' }, [source]), asn.ownerBadge(entry)])
						])
					]),
					E('div', { class: 'xbox-ports', role: 'cell' }, ports.length ? ports : [
						E('span', { class: 'xbox-muted', 'aria-label': '无已记录端口' }, ['—'])
					])
				]);
			});
			table.replaceChildren(E('div', { class: 'xbox-result-row xbox-result-head', role: 'row' }, [
				E('span', { role: 'columnheader' }, ['目标及来源']),
				E('span', { role: 'columnheader' }, ['目标端口'])
			]), ...(rows.length ? rows : [E('p', { class: 'xbox-empty' }, ['没有匹配的条目'])]));
			updateSelected();
		};
		const resetPage = () => { page = 0; drawRows(); };
		this.refreshOwnership = async () => {
			const request = this.request;
			try {
				const result = await this.readSession(session.id, request);
				if (!result || request !== this.request)
					return;
				const owners = new Map(result.entries.filter(entry => entry.owner).map(entry => [entry.value, entry.owner]));
				for (const entry of entries) {
					if (!entry.sources)
						entry.owner = owners.get(entry.value);
				}
				resetPage();
			} catch (error) {
				if (request === this.request)
					errorNotice(error);
			}
		};
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
		}, 'xbox-primary');
		const selection = () => excluded.size ? entries.map((_, i) => excluded.has(i) ? '1' : '0').join('') : '';
		const mrsButton = button('导出或发布 MRS', () => mrs.fromRecording(session.name, session.id, selection()));
		const deleteButton = button('删除这条录制', () => this.confirmRemove([session.id]), 'xbox-danger');

		const notes = [];
		if (session.error)
			notes.push(session.error);
		if (session.storage_warning)
			notes.push(session.storage_warning);
		if (session.truncated)
			notes.push('已达到去重条目上限，部分地址或域名未保存。');
		if (session.ports_truncated)
			notes.push('已达到端口记录上限，部分端口未显示。');
		if (session.kernel_drops)
			notes.push('内核丢失了 ' + session.kernel_drops + ' 个抓包数据包。');
		if (Number.isInteger(session.packet_count)) {
			if (!session.error && captureHint(session))
				notes.push(captureHint(session));
		}

		const device = session.capture_mac && session.capture_mac !== session.device
			? session.device + ' · MAC ' + session.capture_mac : session.device;
		const traffic = Number.isInteger(session.packet_count) ? session.packet_count + ' 个报文 · ' : '';
		this.detail.replaceChildren(
			E('div', { class: 'xbox-panel-head' }, [
				E('h3', {}, [session.name]),
				statusBadge(session.state, states[session.state])
			]),
			E('p', { class: 'xbox-muted' }, [dateTime(session.started) + ' · ' + duration(session.ended - session.started) +
				' · ' + traffic + counts(session)]),
			E('p', { class: 'xbox-muted' }, [session.interface + ' · ' + device]),
			...(session.baseline ? [E('p', { class: 'xbox-muted' }, ['参照基线「' + session.baseline.name + '」'])] : []),
			...notes.map(note => E('p', { class: 'xbox-note' }, [note])),
			E('div', { class: 'xbox-detail-search' }, [
				field('筛选结果', search),
				E('div', { class: 'xbox-actions' }, [
					searchType,
					button('选中匹配项', () => { matches().forEach(({ index }) => excluded.delete(index)); drawRows(); }),
					button('取消匹配项', () => { matches().forEach(({ index }) => excluded.add(index)); drawRows(); })
				])
			]),
			table,
			E('div', { class: 'xbox-paging' }, [previous, paging, next, selected]),
			E('p', { class: 'xbox-muted xbox-port-note' }, [
				'域名端口来自 TLS 握手。普通域名和 IP 规则匹配所有端口。'
			]),
			E('div', { class: 'xbox-export' }, [
				E('div', { class: 'xbox-export-fields' }, [field('导出格式', format), policyField]),
				E('div', { class: 'xbox-actions' }, [download, mrsButton, deleteButton])
			])
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

	confirmRemove(ids) {
		if (!ids.length)
			return;
		const record = this.historyItems.find(session => session.id === ids[0]);
		const message = ids.length === 1 && record ? '删除「' + record.name + '」的录制记录？'
			: '删除选中的 ' + ids.length + ' 条录制记录？';
		const cancel = button('取消', () => ui.hideModal(), 'btn cbi-button');
		const confirm = button('删除', async () => {
			cancel.disabled = true;
			confirm.disabled = true;
			try {
				const result = checked(await removeMany(ids));
				ui.hideModal();
				const removed = new Set(result.removed || []);
				for (const id of removed)
					this.selectedHistory.delete(id);
				if (removed.has(this.detailId)) {
					++this.request;
					this.detailId = null;
					this.refreshOwnership = null;
					this.detail.hidden = true;
				}
				this.historyItems = this.historyItems.filter(session => !removed.has(session.id));
				this.drawHistory();
				if (result.failed?.length)
					errorNotice(new Error('有 ' + result.failed.length + ' 条录制未能删除，可在列表中重试。'));
				await this.refreshHistory();
			} catch (error) {
				errorNotice(error);
				cancel.disabled = false;
				confirm.disabled = false;
			}
		}, 'btn cbi-button cbi-button-remove');
		ui.showModal('删除录制', [
			E('p', {}, [message]),
			E('div', { class: 'right' }, [cancel, ' ', confirm])
		]);
	}
});
