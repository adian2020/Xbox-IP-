'use strict';
'require baseclass';
'require rpc';

const status = rpc.declare({ object: 'xbox-capture', method: 'asn_status', raise: true });
const update = rpc.declare({ object: 'xbox-capture', method: 'asn_update', raise: true });

const namesByAsn = {
	24547: '中国移动（河北）',
	45090: '腾讯云',
	56041: '中国移动（浙江）',
	56046: '中国移动（江苏）',
	56047: '中国移动（湖南）',
	56048: '中国移动（北京）',
	132203: '腾讯云'
};
const organizationAliases = [
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
	[/\bmicrosoft\b/i, '微软'],
	[/\bamazon[.-](?:com|aes|02)\b|amazon web services/i, '亚马逊 AWS'],
	[/\bgoogle[- ]cloud\b/i, '谷歌云'],
	[/\bgoogle\b/i, '谷歌'],
	[/\bapple (?:inc|computer)\b/i, '苹果']
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
	const button = E('button', { type: 'button', class: 'xbox-button', click: () => run(update) }, ['下载归属库']);

	async function run(operation) {
		if (busy)
			return;
		busy = true;
		button.disabled = true;
		try {
			const result = await operation();
			if (typeof result?.loading !== 'boolean')
				throw new Error(result?.error || '归属库服务未响应。');
			const previous = current;
			current = result;
			button.textContent = result.loading ? '更新中…' : result.updated ? '更新归属库' : '下载归属库';
			if (result.loading)
				message.textContent = '正在下载并建立本地归属索引…';
			else if (result.error)
				message.textContent = result.error;
			else if (result.updated)
				message.textContent = result.has_country
					? '本地归属库 · 下载于 ' + new Date(result.updated * 1000).toLocaleString()
					: '点「更新归属库」以显示 ASN 的国家或地区。';
			else
				message.textContent = '下载归属库后可查看 IP 的运营组织、ASN 和国家或地区。';
			if (result.updated && (result.updated !== previous?.updated || result.has_country !== previous?.has_country))
				onUpdated();
		} catch (error) {
			message.textContent = error.message;
		} finally {
			busy = false;
			button.disabled = !!current?.loading;
		}
	}

	const refresh = () => !current || current.loading ? run(status) : null;
	refresh();
	return { button, message, refresh };
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
	const owner = entry.owner;
	if (!owner || !Number.isInteger(owner.asn))
		return '';
	const { fullName, organization, asn } = ownerLabels(owner);
	return E('small', { class: 'xbox-asn-owner', title: [fullName, asn].filter(Boolean).join(' · ') }, [
		[organization, asn].filter(Boolean).join(' · ')
	]);
}

function matchesOwner(entry, query) {
	const owner = entry.owner;
	if (!owner)
		return false;
	const { fullName, organization, asn } = ownerLabels(owner);
	return [organization, fullName, asn, owner.country || ''].some(value => value.toLowerCase().includes(query));
}

return baseclass.extend({ controls, ownerBadge, matchesOwner });
