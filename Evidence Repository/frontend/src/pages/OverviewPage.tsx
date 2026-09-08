import { useEffect, useState } from 'react'
import { clearCredentials, repositoryApi, type EvidenceItem, type EvidenceSource, type TriggerEvent, type WorkGroup } from '../api/api'

const SAMPLE_SIZE = 50

type GroupCoverage = { group: WorkGroup; sources: number; items: number }

type Stats = {
    events: TriggerEvent[]
    eventTotal: number
    groups: WorkGroup[]
    sources: EvidenceSource[]
    items: EvidenceItem[]
    itemTotal: number
    coverage: GroupCoverage[]
}

function formatDate(value: string | null) {
    return value ? new Intl.DateTimeFormat('en-ZA', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) : 'never'
}

function tally<T>(rows: T[], key: (row: T) => string) {
    const counts = new Map<string, number>()
    for (const row of rows) counts.set(key(row), (counts.get(key(row)) ?? 0) + 1)
    return [...counts].sort((a, b) => b[1] - a[1])
}

function isOverdue(source: EvidenceSource, now: number) {
    if (!source.expectedIntervalSeconds) return false
    if (!source.lastEvidenceAt) return true
    return now - new Date(source.lastEvidenceAt).getTime() > source.expectedIntervalSeconds * 1000
}

export default function OverviewPage() {
    const [stats, setStats] = useState<Stats | null>(null)
    const [error, setError] = useState('')

    async function load() {
        try {
            const [eventPage, groups, sources, itemPage] = await Promise.all([
                repositoryApi.listTriggerEvents('', 0, SAMPLE_SIZE),
                repositoryApi.listWorkGroups(),
                repositoryApi.listEvidenceSources(),
                repositoryApi.listEvidenceItems('', false, 0, SAMPLE_SIZE),
            ])
            const totals = await Promise.all(groups.map((group) => repositoryApi
                .listEvidenceItems(group.id, false, 0, 1)
                .then((page) => page.page?.totalElements ?? page.content.length)
                .catch(() => 0)))
            setStats({
                events: eventPage.content,
                eventTotal: eventPage.page?.totalElements ?? eventPage.content.length,
                groups,
                sources,
                items: itemPage.content,
                itemTotal: itemPage.page?.totalElements ?? itemPage.content.length,
                coverage: groups
                    .map((group, index) => ({
                        group,
                        sources: sources.filter((source) => source.workGroupId === group.id).length,
                        items: totals[index],
                    }))
                    .sort((a, b) => b.items - a.items),
            })
            setError('')
        } catch (exception) {
            setError(exception instanceof Error ? exception.message : 'Unable to load repository statistics.')
        }
    }

    useEffect(() => { void load() }, [])

    const now = Date.now()
    const sourceStatuses = tally(stats?.sources ?? [], (source) => source.status)
    const itemStatuses = tally(stats?.items ?? [], (item) => item.status)
    const sourceSystems = new Set((stats?.events ?? []).map((event) => event.sourceSystem)).size
    const silentSources = (stats?.sources ?? []).filter((source) => !source.lastEvidenceAt).length
    const overdueSources = (stats?.sources ?? []).filter((source) => isOverdue(source, now)).length
    const manualItems = (stats?.items ?? []).filter((item) => !item.evidenceSourceId).length
    const unassertedItems = (stats?.items ?? []).filter((item) => !item.eventStart || !item.eventEnd).length

    return <section className="overview-grid">
        <article className="panel spotlight">
            <div className="panel-header"><div><p className="panel-label">Repository overview</p><h2>Evidence intake at a glance</h2></div><button className="text-button" type="button" onClick={() => { clearCredentials(); window.location.reload() }}>Disconnect</button></div>
            <p className="panel-copy">A live summary of the append-only records currently available to investigators.</p>
            {error && <p className="error-message">{error}</p>}
            <div className="metric-row quad">
                <div><span className="metric-value">{stats?.eventTotal ?? '—'}</span><span className="metric-label">trigger events received</span></div>
                <div><span className="metric-value">{stats?.sources.length ?? '—'}</span><span className="metric-label">registered sources</span></div>
                <div><span className="metric-value">{stats?.itemTotal ?? '—'}</span><span className="metric-label">preserved evidence items</span></div>
                <div><span className="metric-value">{stats?.groups.length ?? '—'}</span><span className="metric-label">work groups</span></div>
            </div>
            <p className="metric-footnote">The newest {stats?.events.length ?? 0} trigger events span {sourceSystems} source {sourceSystems === 1 ? 'system' : 'systems'}. Most recent arrival: {formatDate(stats?.events[0]?.receivedAt ?? null)}.</p>
        </article>

        <article className="panel"><p className="panel-label">API surface</p><h2>Available operations</h2><ul className="endpoint-list"><li><code>GET</code> trigger events, filtered and paginated</li><li><code>GET</code> evidence sources, optionally by source key</li><li><code>POST</code> evidence items as verified uploads</li><li><code>GET</code> preserved evidence metadata by id</li></ul></article>

        <article className="panel">
            <div className="panel-header"><div><p className="panel-label">Evidence sources</p><h2>Collector readiness</h2></div><span className="chip">{stats?.sources.length ?? 0} registered</span></div>
            <div className="stat-list">
                {sourceStatuses.map(([status, count]) => <div className="stat-row" key={status}><span className={`status-text ${status.toLowerCase()}`}>{status}</span><strong>{count}</strong></div>)}
                <div className="stat-row"><span>Never reported evidence</span><strong>{silentSources}</strong></div>
                <div className="stat-row"><span>Past expected interval</span><strong className={overdueSources > 0 ? 'stat-warn' : undefined}>{overdueSources}</strong></div>
            </div>
            {stats && stats.sources.length === 0 && <p className="empty-state">No evidence sources are registered yet.</p>}
        </article>

        <article className="panel">
            <div className="panel-header"><div><p className="panel-label">Evidence items</p><h2>Preservation status</h2></div><span className="chip">newest {stats?.items.length ?? 0}</span></div>
            <div className="stat-list">
                {itemStatuses.map(([status, count]) => <div className="stat-row" key={status}><span className={status === 'PRESERVED' ? 'status-pill' : 'status-pill warn'}>{status}</span><strong>{count}</strong></div>)}
                <div className="stat-row"><span>Manually preserved</span><strong>{manualItems}</strong></div>
                <div className="stat-row"><span>No asserted coverage window</span><strong>{unassertedItems}</strong></div>
            </div>
            {stats && stats.items.length === 0 && <p className="empty-state">No evidence items have been preserved yet.</p>}
        </article>

        <article className="panel span-all">
            <div className="panel-header"><div><p className="panel-label">Classification coverage</p><h2>Holdings per work group</h2></div><span className="chip">{stats?.groups.length ?? 0} classifications</span></div>
            <div className="event-table-wrap"><table><thead><tr><th>Work group</th><th>Classification</th><th>Sources</th><th>Evidence items</th><th>Created</th></tr></thead><tbody>{(stats?.coverage ?? []).map(({ group, sources, items }) => <tr key={group.id}><td><strong>{group.name}</strong><small>{group.id}</small></td><td><code>{group.classificationCode}</code></td><td>{sources}</td><td>{items}</td><td>{formatDate(group.createdAt)}</td></tr>)}</tbody></table>{stats && stats.groups.length === 0 && <p className="empty-state">No work groups exist yet, so nothing can be classified.</p>}</div>
        </article>
    </section>
}
