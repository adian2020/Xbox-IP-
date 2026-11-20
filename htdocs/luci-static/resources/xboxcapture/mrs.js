'use strict';
'require baseclass';
'require rpc';
'require ui';

const object = 'xbox-capture';
const login = rpc.declare({ object, method: 'github_login', params: ['token'], raise: true });
const build = rpc.declare({ object, method: 'mrs_build', params: ['id', 'omit'], raise: true });
const status = rpc.declare({ object, method: 'mrs_status', params: ['job'], raise: true });
const read = rpc.declare({ object, method: 'mrs_download', params: ['job', 'kind', 'offset'], raise: true });
const stage = rpc.declare({
	object, method: 'mrs_import', params: ['job', 'kind', 'offset', 'data', 'done'], raise: true
});
const publish = rpc.declare({
	object, method: 'github_publish',
	params: ['token', 'job', 'repository', 'branch', 'directory', 'game', 'domain_name', 'ip_name'], raise: true
});

const kinds = ['domain', 'ipcidr'];
const titles = { domain: '域名', ipcidr: 'IP' };
const actions = { created: '已创建', merged: '已合并', unchanged: '无新增' };
const maxFile = 512 * 1024;
const chunkBytes = 10 * 1024;
let token = '';
const destination = { repository: 'adian2020/Xbox-IP-', branch: '', directory: 'rules' };

function checked(response) {
	if (!response || typeof response !== 'object' || response.error)
		throw new Error(response && response.error || 'MRS 服务返回了无效响应。');
	return response;
}

function field(label, input) {
	const title = E('label', { class: 'cbi-value-title', for: input.id }, [label]);
	return E('div', { class: 'cbi-value' }, [title, E('div', { class: 'cbi-value-field' }, [input])]);
}

function button(label, handler, style) {
	return E('button', { type: 'button', class: 'btn cbi-button ' + (style || ''), click: handler }, [label]);
}

function input(id, value, extra) {
	return E('input', Object.assign({ type: 'text', id: 'xbox-mrs-' + id, value }, extra));
}

function filename(name, defaultName) {
	const value = name.trim() || defaultName;
	return /\.mrs$/i.test(value) ? value : value + '.mrs';
}

async function waitForJob(job) {
	const deadline = Date.now() + 5 * 60 * 1000;
	do {
		const response = checked(await status(job));
		if (response.state === 'ready')
			return response;
		if (response.state !== 'running')
			throw new Error(response.message || 'MRS 操作未完成。');
		await new Promise(resolve => window.setTimeout(resolve, 800));
	} while (Date.now() < deadline);
	throw new Error('等待 MRS 操作超时。请查看目标仓库的提交记录。');
}

async function download(job, kind, name) {
	const parts = [];
	let offset = 0;
	do {
		const response = checked(await read(job, kind, offset));
		parts.push(Uint8Array.from(atob(response.data), value => value.charCodeAt(0)));
		offset = response.next;
	} while (Number.isInteger(offset));
	const url = URL.createObjectURL(new Blob(parts, { type: 'application/octet-stream' }));
	const link = E('a', { href: url, download: name });
	document.body.appendChild(link);
	link.click();
	link.remove();
	window.setTimeout(() => URL.revokeObjectURL(url), 3000);
}

async function importFiles(files, message) {
	let job = '';
	for (const kind of kinds) {
		const file = files[kind];
		if (!file)
			continue;
		if (!/\.mrs$/i.test(file.name) || !file.size || file.size > maxFile)
			throw new Error(titles[kind] + '文件必须是 512 KiB 以内的 .mrs。');

		for (let offset = 0; offset < file.size; offset += chunkBytes) {
			message.textContent = '正在读取' + titles[kind] + ' MRS…';
			const bytes = new Uint8Array(await file.slice(offset, offset + chunkBytes).arrayBuffer());
			const data = btoa(String.fromCharCode(...bytes));
			job = checked(await stage(job, kind, offset, data, offset + bytes.length === file.size)).job;
		}
	}
	if (!job)
		throw new Error('请选择域名或 IP MRS 文件。');
	return job;
}

function showFiles(gameName, prepared) {
	const repository = input('repository', destination.repository, { placeholder: 'owner/repository' });
	const branch = input('branch', destination.branch, { placeholder: '默认分支' });
	const directory = input('directory', destination.directory);
	const game = input('game', gameName.replace(/[\/\\]/g, '-'));
	const names = { domain: input('domain-name', 'domain.mrs'), ipcidr: input('ip-name', 'ip.mrs') };
	const message = E('div', { role: 'status' });
	const files = {};
	const sources = [];
	let busy = false;
	let ticket = '';
	let available = [];

	if (prepared) {
		ticket = prepared.job;
		available = prepared.kinds;
	} else {
		for (const kind of kinds) {
			const file = E('input', { id: 'xbox-mrs-file-' + kind, type: 'file', accept: '.mrs' });
			file.addEventListener('change', () => {
				if (file.files[0])
					names[kind].value = file.files[0].name;
			});
			files[kind] = file;
			sources.push(field(titles[kind] + ' MRS', file));
		}
	}

	const nameFields = kinds.map(kind => field(titles[kind] + '文件名', names[kind]));
	const downloads = available.map(kind => button('下载' + titles[kind] + ' MRS', async () => {
		try {
			await download(ticket, kind, filename(names[kind].value, kind === 'domain' ? 'domain.mrs' : 'ip.mrs'));
		} catch (error) {
			message.textContent = error.message;
		}
	}));

	const save = button('发布到 GitHub', async () => {
		if (busy)
			return;
		busy = true;
		save.disabled = true;
		try {
			if (!token)
				throw new Error('请先在 LuCI 的 GitHub 区域登录。');
			const settings = [repository.value.trim(), branch.value.trim(), directory.value.trim()];
			const gameName = game.value.trim();
			const domainName = filename(names.domain.value, 'domain.mrs');
			const ipName = filename(names.ipcidr.value, 'ip.mrs');
			const credential = token;
			if (!settings[0] || !gameName)
				throw new Error('请填写仓库和游戏或软件目录名。');
			const selected = Object.fromEntries(Object.entries(files).map(([kind, input]) => [kind, input.files[0]]));
			const source = prepared ? ticket : await importFiles(selected, message);
			message.textContent = '正在比对并发布 MRS…';
			const job = checked(await publish(credential, source, ...settings, gameName, domainName, ipName)).job;
			const response = await waitForJob(job);
			[destination.repository, destination.branch, destination.directory] = settings;
			const report = response.report;
			const entries = report.files.map(file => E('li', {}, [actions[file.action] + ' · ' + file.path]));
			message.replaceChildren(
				E('p', {}, [report.commit ? '已提交到 GitHub。' : '当前规则已包含所有条目。']),
				E('ul', {}, entries),
				E('a', { href: report.url, target: '_blank', rel: 'noopener noreferrer' },
					[report.commit ? '查看提交' : '查看目录'])
			);
		} catch (error) {
			message.textContent = error.message;
		} finally {
			busy = false;
			save.disabled = !token;
		}
	}, 'cbi-button-action');
	save.disabled = !token;
	if (!token)
		message.textContent = '登录 GitHub 后即可发布。';

	ui.showModal(prepared ? '录制的 MRS 规则' : '上传已有 MRS', [
		...sources,
		...nameFields,
		...downloads.map(item => E('p', {}, [item])),
		field('GitHub 仓库', repository),
		field('分支', branch),
		field('仓库内目录', directory),
		field('游戏或软件目录名', game),
		E('p', {}, ['同一路径的同名 MRS 会保留原有规则，并加入新条目。']),
		message,
		E('div', { class: 'right' }, [button('关闭', () => ui.hideModal()), ' ', save])
	]);
}

return baseclass.extend({
	render() {
		const password = input('token', '', { type: 'password', autocomplete: 'off', maxlength: 255 });
		const account = E('span', { role: 'status' }, [this.loginName ? '已连接 ' + this.loginName : '尚未连接 GitHub']);
		const importButton = button('上传已有 MRS', () => showFiles('', null));
		const disconnect = button('退出登录', () => {
			token = '';
			this.loginName = '';
			account.textContent = '尚未连接 GitHub';
			importButton.disabled = disconnect.disabled = true;
			connect.disabled = false;
			password.disabled = false;
		});
		const connect = button('登录 GitHub', async () => {
			const secret = password.value.trim();
			password.value = '';
			connect.disabled = true;
			try {
				const response = checked(await login(secret));
				token = secret;
				this.loginName = response.login;
				account.textContent = '已连接 ' + response.login;
				importButton.disabled = disconnect.disabled = false;
				password.disabled = true;
			} catch (error) {
				account.textContent = error.message;
				connect.disabled = false;
			}
		}, 'cbi-button-action');

		importButton.disabled = disconnect.disabled = !token;
		connect.disabled = password.disabled = !!token;
		return E('div', { class: 'cbi-section' }, [
			field('GitHub 访问令牌', password),
			E('p', {}, ['使用目标仓库 Contents 读写权限的 Personal Access Token。生成和合并 MRS 需要 Mihomo 内核。']),
			E('p', {}, [connect, ' ', disconnect, ' ', importButton]),
			E('p', {}, [account])
		]);
	},

	async fromRecording(gameName, id, omit) {
		const progress = E('p', { role: 'status' }, ['正在生成 MRS…']);
		ui.showModal('生成 MRS', [progress]);
		try {
			const job = checked(await build(id, omit)).job;
			const response = await waitForJob(job);
			showFiles(gameName, { job, kinds: response.kinds });
		} catch (error) {
			progress.textContent = error.message;
			progress.parentNode?.appendChild(button('关闭', () => ui.hideModal()));
		}
	}
});
