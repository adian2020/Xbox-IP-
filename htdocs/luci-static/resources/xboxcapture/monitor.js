'use strict';
'require baseclass';
'require rpc';
'require xboxcapture.asn as asn';

const object = 'xbox-capture';
const devices = rpc.declare({ object, method: 'devices', params: ['interface', 'offset'], raise: true });
const live = rpc.declare({ object, method: 'live', params: ['id', 'kind', 'query', 'offset'], raise: true });

function checked(response) {
	if (!response || typeof response !== 'object' || response.error)
		throw new Error(response && response.error || '录制服务返回了无效响应。');
	return response;
}

function button(label, action, style = '') {
	return E('button', { type: 'button', class: 'xbox-button ' + style, click: action }, [label]);
}

function ports(entry) {
	return (entry.ports || []).map(([protocol, port]) =>
		E('span', { class: 'xbox-port', 'data-protocol': protocol }, [protocol + ' ' + port]));
}

function devicePicker(address, interfaceInput) {
	const search = E('input', { type: 'search', placeholder: '搜索设备名称、IP 或 MAC', 'aria-label': '搜索已连接设备' });
	const message = E('p', { class: 'xbox-muted', role: 'status' });
	const items = E('ul', { class: 'xbox-device-list' });
	const selected = E('small', { class: 'xbox-muted xbox-device-selection', hidden: true });
	let records = [];
	let request = 0;
	let truncated = false;
	let loading = false;

	const refresh = button('刷新', () => load());
	const panel = E('div', { id: 'xbox-devices', class: 'xbox-device-picker', hidden: true }, [
		E('div', { class: 'xbox-device-search' }, [search, refresh]),
		message,
		items
	]);
	const trigger = button('选择设备', () => panel.hidden ? open() : close());
	trigger.setAttribute('aria-expanded', 'false');
	trigger.setAttribute('aria-controls', panel.id);

	function close(returnFocus = true) {
		request++;
		panel.hidden = true;
		trigger.setAttribute('aria-expanded', 'false');
		if (returnFocus)
			trigger.focus();
	}

	function open() {
		search.value = '';
		panel.hidden = false;
		trigger.setAttribute('aria-expanded', 'true');
		load();
	}

	function render() {
		if (loading)
			return;
		const query = search.value.trim().toLowerCase();
		const matches = records.filter(device => [device.name, device.mac, ...device.ips, ...device.interfaces]
			.some(value => value.toLowerCase().includes(query)));
		const rows = matches.map(device => {
			const name = device.name || '未知设备';
			const button = E('button', {
				type: 'button', class: 'xbox-device-option',
				click: () => {
					address.value = device.mac;
					if (interfaceInput.value !== 'any' && device.interfaces.length === 1)
						interfaceInput.value = device.interfaces[0];
					selected.textContent = name + ' · ' + device.ips.join(' / ');
					selected.hidden = false;
					close();
				}
			}, [
				E('strong', { class: 'xbox-device-name' }, [name]),
				E('span', { class: 'xbox-device-ips' }, device.ips.map(ip =>
					E('span', { class: 'xbox-device-ip' }, [ip]))),
				E('small', { class: 'xbox-muted' }, [device.mac + ' · ' + device.interfaces.join(' / ')])
			]);
			return E('li', {}, [button]);
		});
		items.replaceChildren(...rows);
		const suffix = truncated ? ' · 达到列表上限' : '';
		message.textContent = rows.length ? '发现 ' + rows.length + ' 台设备' + suffix
			: records.length ? '没有匹配的设备。' : '暂无已发现的设备，可手动填写地址。';
	}

	async function load() {
		const generation = ++request;
		loading = true;
		refresh.disabled = true;
		message.textContent = '正在读取设备…';
		items.replaceChildren();
		try {
			let offset = 0;
			const discovered = new Map();
			const interfaceName = interfaceInput.value.trim() || 'br-lan';
			do {
				const result = checked(await devices(interfaceName, offset));
				if (generation !== request)
					return;
				for (const device of result.devices)
					discovered.set(device.mac, device);
				truncated = result.truncated;
				offset = result.next;
			} while (Number.isInteger(offset));
			records = [...discovered.values()];
			loading = false;
			render();
		} catch (error) {
			if (generation === request) {
				records = [];
				items.replaceChildren();
				message.textContent = error.message;
			}
		} finally {
			if (generation === request) {
				loading = false;
				refresh.disabled = false;
			}
		}
	}

	search.addEventListener('input', render);
	panel.addEventListener('keydown', event => {
		if (event.key === 'Escape')
			close();
	});
	address.addEventListener('input', () => { selected.hidden = true; });
	return E('div', { class: 'xbox-device-control' }, [
		E('div', { class: 'xbox-device-input' }, [address, trigger]),
		selected,
		panel
	]);
}

function captureMonitor(openRecord, canAuto) {
	let active = null;
	let available = null;
	let trackedId = null;
	let lastPage = null;
	let offset = 0;
	let pending = '';
	let generation = 0;
	let searchTimer;
	const badge = E('span', { class: 'xbox-monitor-badge', role: 'status' });
	const context = E('p', { class: 'xbox-monitor-context' });
	const search = E('input', {
		type: 'search', maxlength: 128, placeholder: '搜索域名、IP 或端口', 'aria-label': '搜索实时抓取结果'
	});
	const kind = E('select', { 'aria-label': '实时抓取类型' }, [
		E('option', { value: 'all' }, ['全部类型']),
		E('option', { value: 'domain' }, ['域名']),
		E('option', { value: 'ip' }, ['公网 IP'])
	]);
	const list = E('ul', { class: 'xbox-monitor-list', 'aria-label': '实时抓取结果' });
	const message = E('p', { class: 'xbox-monitor-message', role: 'status' });
	const previous = button('上一页', () => navigate(lastPage.previous));
	const next = button('下一页', () => navigate(lastPage.next));
	const complete = button('查看完整录制', () => openRecord(trackedId));
	const hide = button('收起', () => toggle());
	const panel = E('section', { class: 'xbox-panel xbox-monitor', id: 'xbox-monitor', hidden: true }, [
		E('header', { class: 'xbox-monitor-head' }, [
			E('div', {}, [E('h3', {}, ['抓取面板']), context]),
			E('div', { class: 'xbox-monitor-head-actions' }, [badge, hide])
		]),
		E('div', { class: 'xbox-monitor-controls' }, [search, kind]),
		list,
		E('div', { class: 'xbox-monitor-foot' }, [message,
			E('div', { class: 'xbox-monitor-controls' }, [previous, next, complete])
		])
	]);
	const trigger = button('打开抓取面板', () => toggle(), 'xbox-monitor-trigger');
	trigger.setAttribute('aria-expanded', 'false');
	trigger.setAttribute('aria-controls', panel.id);

	function navigate(newOffset) {
		offset = newOffset;
		load();
	}

	function toggle() {
		const open = panel.hidden;
		panel.hidden = !open;
		trigger.textContent = open ? '收起抓取面板' : '打开抓取面板';
		trigger.setAttribute('aria-expanded', String(open));
		if (open) {
			draw();
			panel.scrollIntoView({ block: 'start' });
			load();
		} else {
			generation++;
			pending = '';
			trigger.focus({ preventScroll: true });
		}
	}

	function draw() {
		badge.textContent = available === false ? '服务未响应' : active ? '实时更新' : trackedId ? '已结束' : '等待录制';
		badge.setAttribute('data-live', String(!!active && available === true));
		const summary = active
			? active.name + ' · ' + active.interface + ' · ' + active.domain_count + ' 个域名 · ' + active.ip_count + ' 个公网 IP'
			: trackedId ? '录制已结束，结果已保存到录制记录。' : '开始录制后，域名和公网 IP 会显示在这里。';
		context.textContent = summary;
		search.disabled = kind.disabled = !active;
		previous.disabled = !active || !Number.isInteger(lastPage?.previous);
		next.disabled = !active || !Number.isInteger(lastPage?.next);
		complete.hidden = !!active || !trackedId;
		const page = lastPage;
		if (page?.entries.length) {
			message.textContent = (page.offset + 1) + '–' + (page.offset + page.entries.length) + ' / ' + page.total + ' 条';
		} else {
			message.textContent = active && (search.value || kind.value !== 'all')
				? '暂无匹配结果。' : active ? '等待采集数据…' : '暂无实时数据。';
		}
	}

	async function load() {
		if (panel.hidden || !active || available !== true)
			return;
		const target = active.id;
		const query = search.value.trim();
		const key = JSON.stringify([target, kind.value, query, offset]);
		if (pending === key)
			return;

		pending = key;
		const request = ++generation;
		try {
			const page = checked(await live(target, kind.value, query, offset));
			if (request !== generation || page.id !== active?.id)
				return;
			if (JSON.stringify(lastPage) !== JSON.stringify(page)) {
				lastPage = page;
				offset = page.offset;
				list.replaceChildren(...page.entries.map(entry => {
					const found = ports(entry);
					const source = entry.sources?.join(' / ') || (entry.value.includes(':') ? 'IPv6' : 'IPv4');
					return E('li', { class: 'xbox-monitor-row' }, [
						E('div', { class: 'xbox-monitor-target' }, [
							E('strong', {}, [entry.value]),
							E('small', {}, [source]),
							asn.ownerBadge(entry),
							asn.lookupButton(entry, page.id, load)
						]),
						E('div', { class: 'xbox-ports' }, found.length ? found : [E('span', {}, ['—'])]),
						E('time', {}, [new Date(entry.seen * 1000).toLocaleTimeString()])
					]);
				}));
			}
			draw();
			if (canAuto())
				await asn.runAutomatic(target, page.entries).catch(() => {});
		} catch (error) {
			if (request === generation)
				message.textContent = error.message;
		} finally {
			if (request === generation)
				pending = '';
		}
	}

	function reset() {
		generation++;
		pending = '';
		offset = 0;
		lastPage = null;
		list.replaceChildren();
		draw();
	}

	kind.addEventListener('change', () => { reset(); load(); });
	search.addEventListener('input', () => {
		window.clearTimeout(searchTimer);
		reset();
		searchTimer = window.setTimeout(() => load(), 220);
	});

	return {
		button: trigger,
		panel,
		update(session, ready) {
			const before = active?.id;
			active = session;
			available = ready;
			if (session && session.id !== trackedId) {
				trackedId = session.id;
				reset();
			} else if (before && !session) {
				generation++;
				pending = '';
			}
			draw();
			return load();
		}
	};
}

return baseclass.extend({ devicePicker, captureMonitor, ports });
