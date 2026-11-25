'use strict';
'require baseclass';
'require rpc';
'require ui';

const status = rpc.declare({ object: 'xbox-capture', method: 'asn_status', raise: true });
const update = rpc.declare({ object: 'xbox-capture', method: 'asn_update', raise: true });
const lookup = rpc.declare({ object: 'xbox-capture', method: 'domain_lookup',
	params: ['id', 'domain', 'resolver'], raise: true });

const namesByAsn = {
	3462: '中华电信',
	4134: '中国电信',
	24547: '中国移动（河北）',
	45090: '腾讯云',
	56041: '中国移动（浙江）',
	56046: '中国移动（江苏）',
	56047: '中国移动（湖南）',
	56048: '中国移动（北京）',
	132203: '腾讯云'
};
const organizationAliases = [
	[/\bakamai\b/i, '阿卡迈'],
	[/\b(?:alibaba|aliyun)\b/i, '阿里云'],
	[/china mobile international|\bcmi-int-/i, '中国移动国际'],
	[/china ?mobile|\bcmnet-/i, '中国移动'],
	[/china ?telecom|\bchinanet\b/i, '中国电信'],
	[/china ?unicom|\bchina169\b/i, '中国联通'],
	[/china broadcasting network/i, '中国广电'],
	[/\btencent\b/i, '腾讯'],
	[/huawei cloud|hwclouds/i, '华为云'],
	[/\bhuawei\b/i, '华为'],
	[/\bbaidu\b/i, '百度'],
	[/kingsoft cloud|\bksyun\b/i, '金山云'],
	[/\bbytedance\b/i, '字节跳动'],
	[/china education and research network|\bcernet\b/i, '中国教育和科研计算机网'],
	[/\b(?:chinanetcenter|wangsu)\b/i, '网宿科技'],
	[/\b21vianet\b/i, '世纪互联'],
	[/\bgds\b.*data service|\bglobal data solutions\b/i, '万国数据'],
	[/\bzenlayer\b/i, '禅层科技'],
	[/\bmicrosoft\b/i, '微软'],
	[/\bamazon[.-](?:com|aes|02)\b|amazon web services/i, '亚马逊 AWS'],
	[/\bgoogle[- ]cloud\b/i, '谷歌云'],
	[/\bgoogle\b/i, '谷歌'],
	[/\bapple (?:inc|computer)\b/i, '苹果'],
	[/\boracle\b/i, '甲骨文'],
	[/\bibm\b|\binternational business machines\b/i, '国际商业机器公司（IBM）'],
	[/\bmeta platforms\b|\bfacebook\b/i, '脸书（Meta）'],
	[/\bnetflix\b/i, '奈飞'],
	[/\bcomcast\b/i, '康卡斯特'],
	[/\bverizon\b/i, '威瑞森'],
	[/\bat&t\b/i, '美国电话电报公司（AT&T）'],
	[/\bcharter communications\b/i, '宪章通信'],
	[/\bcenturylink\b/i, '世纪链路通信'],
	[/\blumen technologies\b/i, '流明科技'],
	[/\bdeutsche telekom\b/i, '德国电信'],
	[/\borange (?:s\.?a\.?|espagne|polska|romania|business)\b/i, '奥兰治电信'],
	[/\bbritish (?:telecommunications|telecom)\b/i, '英国电信'],
	[/\bvodafone\b/i, '沃达丰'],
	[/\btelia\b/i, '特利亚电信'],
	[/\btelenor\b/i, '挪威电信'],
	[/\brostelecom\b/i, '俄罗斯电信'],
	[/\btelefonica\b|\btelefónica\b/i, '西班牙电信'],
	[/\bkorea telecom\b|\bkornet\b/i, '韩国电信'],
	[/\bsk broadband\b/i, 'SK 宽带'],
	[/\bntt\b/i, '日本电信电话（NTT）'],
	[/\bsoftbank\b/i, '软银'],
	[/\bsingtel\b|\bsingapore telecommunications\b/i, '新加坡电信'],
	[/\bstarhub\b/i, '星和电信'],
	[/\btelstra\b/i, '澳大利亚电信'],
	[/\b(?:hkt|pccw)\b/i, '香港电讯'],
	[/\bhgc global communications\b/i, '和记环球电讯'],
	[/\bhong kong broadband network\b|\bhkbn\b/i, '香港宽频'],
	[/\bhinet\b|\bchunghwa telecom\b/i, '中华电信'],
	[/\bequinix\b/i, '易昆尼克斯']
];
const regionOverrides = {
	CN: '中国', US: '美国', HK: '中国香港', MO: '中国澳门', TW: '中国台湾',
	AP: '亚太地区', ZZ: '未知地区'
};
const regions = typeof Intl.DisplayNames === 'function'
	? new Intl.DisplayNames(['zh-CN'], { type: 'region', fallback: 'none' }) : null;

function controls(onUpdated) {
	let current = null;
	let busy = false;
	const message = E('small', { class: 'xbox-muted xbox-asn-status', role: 'status' });
	const bar = E('progress', { class: 'xbox-asn-progress', max: 100, hidden: true, 'aria-label': '归属库更新进度' });
	const button = E('button', { type: 'button', class: 'xbox-button', click: () => run(update) }, ['下载归属库']);

	function showProgress(progress) {
		const { stage, done = 0, total, rows = 0 } = progress || {};
		const percent = total > 0 ? Math.min(100, Math.floor(done / total * 100)) : null;
		bar.hidden = false;
		if (percent === null || stage === 'finalize')
			bar.removeAttribute('value');
		else
			bar.value = percent;
		if (stage === 'download') {
			const mib = bytes => (bytes / 1048576).toFixed(1);
			message.textContent = '下载归属库 · ' + mib(done) +
				(percent === null ? ' MiB' : ' / ' + mib(total) + ' MiB · ' + percent + '%');
		} else if (stage === 'index') {
			message.textContent = '建立索引 · 已处理 ' + rows.toLocaleString('zh-CN') + ' 条' +
				(percent === null ? '' : ' · 已读取 ' + percent + '%');
		} else if (stage === 'finalize') {
			message.textContent = '写入本地索引 · 已处理 ' + rows.toLocaleString('zh-CN') + ' 条';
		} else {
			message.textContent = '正在连接归属库下载源…';
		}
	}

	async function run(operation) {
		if (busy)
			return;
		busy = true;
		button.disabled = true;
		if (operation === update)
			showProgress();
		try {
			const result = await operation();
			if (typeof result?.loading !== 'boolean')
				throw new Error(result?.error || '归属库服务未响应。');
			const previous = current;
			current = result;
			button.textContent = result.loading ? '更新中…' : result.updated ? '更新归属库' : '下载归属库';
			bar.hidden = !result.loading;
			if (result.loading)
				showProgress(result.progress);
			else if (result.error)
				message.textContent = result.error;
			else if (result.updated)
				message.textContent = result.has_country
					? (previous?.loading ? '归属库已更新 · ' : '本地归属库 · 下载于 ') +
						new Date(result.updated * 1000).toLocaleString()
					: '点「更新归属库」以显示 ASN 的国家或地区。';
			else
				message.textContent = '下载归属库后可查看域名和 IP 的运营组织、ASN 和国家或地区。';
			if (!result.loading && result.updated &&
				(result.updated !== previous?.updated || result.has_country !== previous?.has_country ||
					(previous?.loading && !result.error)))
				onUpdated();
		} catch (error) {
			bar.hidden = !current?.loading;
			message.textContent = error.message;
		} finally {
			busy = false;
			button.disabled = !!current?.loading;
		}
	}

	const refresh = () => !current || current.loading ? run(status) : null;
	refresh();
	return { button, message, bar, refresh };
}

function ownerLabels(owner) {
	const fullName = owner.organization || '';
	const separator = fullName.indexOf(' - ');
	const shortName = separator < 0 ? fullName : fullName.slice(separator + 3) || fullName;
	const alias = namesByAsn[owner.asn] || organizationAliases.find(([pattern]) => pattern.test(fullName))?.[1];
	const country = owner.country;
	const region = typeof country === 'string' && /^[A-Z]{2}$/.test(country)
		? regionOverrides[country] || regions?.of(country) || country
		: country === null ? '未知地区' : '';
	const number = 'AS' + owner.asn;
	return { fullName, organization: alias || shortName, asn: region ? number + '(' + region + ')' : number };
}

function ownerBadge(entry) {
	const owners = (entry.owners || [entry.owner]).filter(owner => Number.isInteger(owner?.asn));
	if (!owners.length)
		return '';
	const firstSource = owners[0].source;
	const badges = owners.map(owner => {
		const { fullName, organization, asn } = ownerLabels(owner);
		return E('small', { class: 'xbox-asn-owner', title: [fullName, asn, owner.source].filter(Boolean).join(' · ') }, [
			[organization, asn].filter(Boolean).join(' · ')
		]);
	});
	if (firstSource?.endsWith('补查'))
		badges.unshift(E('small', { class: 'xbox-muted xbox-asn-lookup-source' }, [firstSource]));
	return E('span', { class: 'xbox-asn-owners' }, badges);
}

function showLookup(id, domain, onFound) {
	let open = true;
	const resolver = E('select', { 'aria-label': '补查 DNS' }, [
		E('option', { value: 'system' }, ['路由器 DNS']),
		E('option', { value: 'alidns' }, ['阿里公共 DNS'])
	]);
	const result = E('div', { role: 'status' });
	const query = E('button', { type: 'button', class: 'btn cbi-button cbi-button-action', click: run }, ['查询']);
	const close = E('button', { type: 'button', class: 'btn cbi-button', click: () => {
		open = false;
		ui.hideModal();
	}}, ['关闭']);

	async function run() {
		query.disabled = resolver.disabled = true;
		result.textContent = '正在查询域名归属…';
		try {
			let response = await lookup(id, domain, resolver.value);
			for (let retries = 0; open && response?.pending && retries < 24; retries++) {
				await new Promise(resolve => setTimeout(resolve, 500));
				if (open)
					response = await lookup(id, domain, '');
			}
			if (!open)
				return;
			if (response?.error || !response?.owners?.length)
				throw new Error(response?.error || '补查暂未完成，请稍后重试。');
			result.replaceChildren(ownerBadge(response));
			onFound();
		} catch (error) {
			if (open)
				result.textContent = error.message;
		} finally {
			query.disabled = resolver.disabled = false;
		}
	}

	ui.showModal('补查域名归属', [
		E('p', {}, [E('strong', {}, [domain])]),
		E('p', {}, ['确认后会向所选 DNS 查询此域名。解析结果可能随时间和网络变化。']),
		resolver, result,
		E('div', { class: 'right' }, [close, ' ', query])
	]);
}

function lookupButton(entry, id, onFound) {
	if (!entry.sources || entry.owners?.length)
		return '';
	return E('button', {
		type: 'button', class: 'xbox-asn-query',
		'aria-label': '补查域名归属 ' + entry.value,
		click: () => showLookup(id, entry.value, onFound)
	}, ['补查归属']);
}

function matchesOwner(entry, query) {
	return (entry.owners || [entry.owner]).some(owner => {
		if (!owner)
			return false;
		const { fullName, organization, asn } = ownerLabels(owner);
		return [organization, fullName, asn, owner.country || ''].some(value => value.toLowerCase().includes(query));
	});
}

return baseclass.extend({ controls, ownerBadge, lookupButton, matchesOwner });
