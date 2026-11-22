'use strict';
'require baseclass';
'require rpc';

const status = rpc.declare({ object: 'xbox-capture', method: 'asn_status', raise: true });
const update = rpc.declare({ object: 'xbox-capture', method: 'asn_update', raise: true });

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
			const previous = current?.updated;
			current = result;
			button.textContent = result.loading ? '更新中…' : result.updated ? '更新归属库' : '下载归属库';
			if (result.loading)
				message.textContent = '正在下载并建立本地归属索引…';
			else if (result.error)
				message.textContent = result.error;
			else if (result.updated)
				message.textContent = '本地归属库 · 下载于 ' + new Date(result.updated * 1000).toLocaleString();
			else
				message.textContent = '下载归属库后可在 IP 下查看 ASN 和运营组织。';
			if (result.updated && result.updated !== previous)
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

function ownerBadge(entry) {
	const owner = entry.owner;
	if (!owner || !Number.isInteger(owner.asn))
		return '';
	const fullName = owner.organization || '';
	const separator = fullName.indexOf(' - ');
	const organization = separator < 0 ? fullName : fullName.slice(separator + 3) || fullName;
	const number = 'AS' + owner.asn;
	return E('small', { class: 'xbox-asn-owner', title: [fullName, number].filter(Boolean).join(' · ') }, [
		[organization, number].filter(Boolean).join(' · ')
	]);
}

function matchesOwner(entry, query) {
	const owner = entry.owner;
	return owner && (('as' + owner.asn).includes(query) || owner.organization?.toLowerCase().includes(query));
}

return baseclass.extend({ controls, ownerBadge, matchesOwner });
